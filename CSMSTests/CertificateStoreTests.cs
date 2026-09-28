/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of CSMS <https://github.com/OpenChargingCloud/CSMS>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The certificate store of the node below a CSMS, over the wire: the
    /// kinds it keeps, and what a TLS root is for - said at the upload,
    /// changed afterwards, taken back to every use - and a usage the CSMS does
    /// not know refused where it is typed.
    /// </summary>
    public class CertificateStoreTests
    {

        #region Data

        private String       directory  = "";
        private CSMS?        csms;
        private HttpClient?  client;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory  = TestCSMSs.TemporaryDirectory("certificates");

            // The store is where the node puts it when nobody says otherwise:
            // "certificates" beside the configuration file.
            csms       = TestCSMSs.New(directory, TestCSMSs.Offline);

            await csms.Start();

            client     = new HttpClient {
                             BaseAddress  = new Uri(csms.WebInterfaceURL.ToString()),
                             Timeout      = TimeSpan.FromSeconds(30)
                         };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                             "Basic",
                                                             Convert.ToBase64String(Encoding.UTF8.GetBytes($"root:{csms.GeneratedPassword}"))
                                                         );

        }

        [TearDown]
        public async Task TearDown()
        {

            client?.Dispose();

            if (csms is not null)
                await csms.DisposeAsync();

            csms = null;

            TestCSMSs.Remove(directory);

        }

        #endregion


        #region (helpers) RootPem(Name) / Send(Method, Path, JSON)

        /// <summary>
        /// A self-signed certificate, as the text of a PEM file base64-encoded -
        /// which is what an upload from the browser turns into.
        /// </summary>
        private static String RootPem(String Name)
        {

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request    = new CertificateRequest($"CN={Name}", key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            using var root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            return Convert.ToBase64String(Encoding.ASCII.GetBytes(root.ExportCertificatePem()));

        }

        private async Task<(HttpStatusCode Status, JObject JSON)> Send(HttpMethod  Method,
                                                                      String      Path,
                                                                      JObject?    JSON = null)
        {

            using var request   = new HttpRequestMessage(Method, Path);

            if (JSON is not null)
                request.Content = new StringContent(JSON.ToString(), Encoding.UTF8, "application/json");

            using var response  = await client!.SendAsync(request);
            var text            = await response.Content.ReadAsStringAsync();

            return (response.StatusCode, text.Length > 0 ? JObject.Parse(text) : new JObject());

        }

        #endregion


        #region ACSMSKeepsTheRootsOfISO15118AndTheKindsOfTLS()

        /// <summary>
        /// The kinds a CSMS keeps: the three roots of the PKI of ISO 15118 and
        /// the four kinds of TLS, grouped as the page shows them - and none of a
        /// vehicle's own credentials, which is refused before anything is read.
        /// </summary>
        [Test]
        public async Task ACSMSKeepsTheRootsOfISO15118AndTheKindsOfTLS()
        {

            var (_, store)             = await Send(HttpMethod.Get, "api/v1/certificates");

            var (refused, refusal)     = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                        new JProperty("kind",     "vehicle"),
                                                        new JProperty("content",  RootPem("Not A Vehicle"))
                                                    ));

            Assert.Multiple(() => {

                Assert.That(((JObject) store["kinds"]!).Properties().Select(kind => kind.Name),
                            Is.EqualTo(new[] { "v2gRoot", "moRoot", "oemRoot", "tlsRoot", "clientRoot", "tlsServer", "tlsIdentity" }));

                Assert.That(store["trustAnchors"]!.Values<String>(),  Is.EqualTo(new[] { "v2gRoot", "moRoot", "oemRoot", "tlsRoot", "clientRoot" }));
                Assert.That(store["credentials"]!.Values<String>(),   Is.EqualTo(new[] { "tlsIdentity" }));
                Assert.That(store["recognised"]!.Values<String>(),    Is.EqualTo(new[] { "tlsServer" }));

                Assert.That(Directory.Exists(Path.Combine(directory, "certificates")), Is.True,
                            "the store is beside the configuration file");

                Assert.That(refused,                                  Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(refusal.ToString(),                       Does.Contain("'kind' has to be one of v2gRoot, moRoot, oemRoot, tlsRoot, clientRoot, tlsServer, tlsIdentity."),
                            "the node's API names the kinds this store keeps");

            });

        }

        #endregion

        #region ARootIsUploadedForTheUsesItIsFor()

        [Test]
        public async Task ARootIsUploadedForTheUsesItIsFor()
        {

            var (created, entry) = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                  new JProperty("kind",     "tlsRoot"),
                                                  new JProperty("content",  RootPem("Our Clocks' Root")),
                                                  new JProperty("usages",   new JArray("nts"))
                                              ));

            var (_, store)       = await Send(HttpMethod.Get, "api/v1/certificates");

            Assert.Multiple(() => {

                Assert.That(created,                                                  Is.EqualTo(HttpStatusCode.Created), entry.ToString());
                Assert.That(entry["usages"]!.Values<String>(),                        Is.EqualTo(new[] { "nts" }));

                Assert.That(store["usages"]!.Values<String>(),                        Is.EqualTo(new[] { "dns", "nts" }), "what a page may offer");
                Assert.That(store["kinds"]!["tlsRoot"]!["hasUsages"]!.Value<Boolean>(),  Is.True);
                Assert.That(store["kinds"]!["v2gRoot"]!["hasUsages"]!.Value<Boolean>(),  Is.False);
                Assert.That(store["kinds"]!["tlsRoot"]!["usages"]!.Values<String>(),     Is.EqualTo(new[] { "dns", "nts" }), "what a page may offer a root");
                Assert.That(store["kinds"]!["tlsServer"]!["usages"]!.Values<String>(),   Is.EqualTo(new[] { "dns", "nts" }));
                Assert.That(store["kinds"]!["tlsIdentity"]!["hasUsages"]!.Value<Boolean>(), Is.False,
                            "a CSMS names no listener an identity could be told of, so a page offers it nothing - not the services a root vouches for");
                Assert.That(store["kinds"]!["tlsIdentity"]!["usages"]!.Children().Any(),  Is.False);
                Assert.That(store["certificates"]!["tlsRoot"]![0]!["usages"]!.Values<String>(),  Is.EqualTo(new[] { "nts" }));
                Assert.That(store["certificates"]!["v2gRoot"]!.Children().Any(),      Is.False);

                Assert.That(store["trustAnchors"]!.Values<String>(),                  Does.Contain("tlsRoot"));
                Assert.That(store["recognised"]!.Values<String>(),                    Is.EqualTo(new[] { "tlsServer" }),
                            "a server certificate is recognised, neither believed nor presented");
                Assert.That(store["credentials"]!.Values<String>(),                   Does.Not.Contain("tlsServer").And.Contain("tlsIdentity"));

            });

        }

        #endregion

        #region WhatARootIsForIsChangedAndTakenBackToEveryUse()

        [Test]
        public async Task WhatARootIsForIsChangedAndTakenBackToEveryUse()
        {

            var (_, entry)        = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                   new JProperty("kind",     "tlsRoot"),
                                                   new JProperty("content",  RootPem("Our Resolvers' Root")),
                                                   new JProperty("usages",   new JArray("dns"))
                                               ));

            var path              = $"api/v1/certificates/{entry["id"]}";

            var (both,  forBoth)  = await Send(HttpMethod.Patch, path, new JObject(new JProperty("usages", new JArray("nts", "dns"))));
            var (label, relabel)  = await Send(HttpMethod.Patch, path, new JObject(new JProperty("label",  "Our Root")));
            var (every, forAll)   = await Send(HttpMethod.Patch, path, new JObject(new JProperty("usages", JValue.CreateNull())));

            Assert.Multiple(() => {
                Assert.That(both,                                      Is.EqualTo(HttpStatusCode.OK), forBoth.ToString());
                Assert.That(forBoth["usages"]!.Values<String>(),       Is.EqualTo(new[] { "dns", "nts" }));
                Assert.That(relabel["usages"]!.Values<String>(),       Is.EqualTo(new[] { "dns", "nts" }), "a PATCH without them leaves them alone");
                Assert.That(every,                                     Is.EqualTo(HttpStatusCode.OK), forAll.ToString());
                Assert.That(forAll["usages"]!.Type,                    Is.EqualTo(JTokenType.Null),    "null is every use again");
                Assert.That(csms!.Log.Recent(200, Tag: "security").Any(line => line.Message.Contains("is now for every use")),
                            Is.True,
                            "a change of what a root vouches for is a matter of security, and said as one");
            });

        }

        #endregion

        #region WhatIsNotAUsageIsRefusedWhereItIsTyped()

        [Test]
        public async Task WhatIsNotAUsageIsRefusedWhereItIsTyped()
        {

            var (unknown, said)     = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                     new JProperty("kind",     "tlsRoot"),
                                                     new JProperty("content",  RootPem("Some Root")),
                                                     new JProperty("usages",   new JArray("ntp"))
                                                 ));

            var (onV2G, v2gSaid)    = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                     new JProperty("kind",     "v2gRoot"),
                                                     new JProperty("content",  RootPem("A V2G Root")),
                                                     new JProperty("usages",   new JArray("nts"))
                                                 ));

            var (notAList, listSaid) = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                     new JProperty("kind",     "tlsRoot"),
                                                     new JProperty("content",  RootPem("Another Root")),
                                                     new JProperty("usages",   "dns")
                                                 ));

            // Refused before the file is read, so a root's file does for an
            // identity here: what is wrong is what it was to be told.
            var (identity, idSaid)  = await Send(HttpMethod.Post, "api/v1/certificates", new JObject(
                                                     new JProperty("kind",     "tlsIdentity"),
                                                     new JProperty("content",  RootPem("Not An Identity")),
                                                     new JProperty("usages",   new JArray("dns"))
                                                 ));

            var (_, store)          = await Send(HttpMethod.Get, "api/v1/certificates");

            Assert.Multiple(() => {
                Assert.That(unknown,                       Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(said.ToString(),               Does.Contain("'ntp' is not a usage this CSMS knows").And.Contain("dns, nts"));
                Assert.That(onV2G,                         Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(v2gSaid.ToString(),            Does.Contain("only a TLS root and a server certificate"));
                Assert.That(notAList,                      Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(listSaid.ToString(),           Does.Contain("has to be a list of usages"));
                Assert.That(identity,                      Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(idSaid.ToString(),             Does.Contain("names none"), "an identity is told listeners, and a CSMS has none");
                Assert.That(store["certificates"]!.Values().SelectMany(kind => kind.Children()).Any(),
                            Is.False,
                            "nothing refused was half-imported");
            });

        }

        #endregion

    }

}
