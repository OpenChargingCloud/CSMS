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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What this CSMS says it is, and what happens when somebody
    /// tells it to be something else.
    /// </summary>
    public class ConfigurationAPITests : ACSMSTests
    {

        #region TheStatusResourceSaysWhatIsRunning()

        [Test]
        public async Task TheStatusResourceSaysWhatIsRunning()
        {

            using var http = await SignedIn();

            var status = await GetJSON(http, "/api/v1/status");

            Assert.Multiple(() => {
                Assert.That(status.Value<String>("service"),  Is.EqualTo("CSMS"));
                Assert.That(status.Value<String>("version"),  Is.EqualTo(CSMS.Version));
                Assert.That(status.Value<String>("ocppId"),   Is.EqualTo(CSMS.Node.Id.ToString()));
                Assert.That(status.Value<Int32> ("sessions"), Is.EqualTo(1));
                Assert.That(status["log"]?.Value<Int32>("capacity"), Is.GreaterThan(0));
            });

        }

        #endregion

        #region TheConfigurationNamesEverySection()

        /// <summary>
        /// The Configuration page renders whatever the CSMS sends rather
        /// than a list of its own, so a section going missing is not a broken
        /// page - it is a page that quietly stops mentioning something.
        /// </summary>
        [Test]
        public async Task TheConfigurationNamesEverySection()
        {

            using var http = await SignedIn();

            var configuration = await GetJSON(http, "/api/v1/configuration");

            Assert.Multiple(() => {
                Assert.That(configuration["CSMS"], Is.Not.Null);
                Assert.That(configuration["http"],       Is.Not.Null);
                Assert.That(configuration["web"],        Is.Not.Null);
                Assert.That(configuration["log"],        Is.Not.Null);
                Assert.That(configuration["time"],       Is.Not.Null);
                Assert.That(configuration["ocpp"],       Is.Not.Null);
                Assert.That(configuration["assemblies"], Is.TypeOf<JArray>());
            });

        }

        #endregion

        #region TheConfigurationNeverCarriesThePassword()

        /// <summary>
        /// The accounts appear in the configuration as the path they live at
        /// and the route to sign in, and never with anything about a password -
        /// neither a password nor its hash.
        /// </summary>
        [Test]
        public async Task TheConfigurationNeverCarriesThePassword()
        {

            using var http = await SignedIn();

            var configuration = (await GetJSON(http, "/api/v1/configuration")).ToString();

            Assert.Multiple(() => {
                Assert.That(configuration.Contains(Password, StringComparison.Ordinal),   Is.False,
                            "The configuration carries the password in the clear.");
                Assert.That(configuration.Contains("$pbkdf2", StringComparison.Ordinal),  Is.False,
                            "The configuration carries the password hash, which is worth a dictionary attack.");
            });

        }

        #endregion

        #region TheOCPPSectionDescribesTheNode()

        [Test]
        public async Task TheOCPPSectionDescribesTheNode()
        {

            using var http = await SignedIn();

            var ocpp = (await GetJSON(http, "/api/v1/configuration"))["ocpp"];

            Assert.Multiple(() => {
                Assert.That(ocpp?.Value<String>("version"),  Is.EqualTo("2.1"));
                Assert.That(ocpp?.Value<String>("role"),     Is.EqualTo("CSMS"));
                Assert.That(ocpp?.Value<String>("id"),       Is.EqualTo(CSMS.Node.Id.ToString()));
                Assert.That(ocpp?.Value<String>("vendor"),   Is.EqualTo(CSMS.Node.VendorName));
                Assert.That(ocpp?.Value<String>("model"),    Is.EqualTo(CSMS.Node.Model));
            });

        }

        #endregion


        #region TheDNSConfigurationIsReadable()

        [Test]
        public async Task TheDNSConfigurationIsReadable()
        {

            using var http = await SignedIn();

            var dns = await GetJSON(http, "/api/v1/configuration/dns");

            Assert.Multiple(() => {
                Assert.That(dns.Value<Boolean>("enabled"),   Is.True);
                Assert.That(dns["servers"],                  Is.TypeOf<JArray>());
                Assert.That(dns["settings"],                 Is.Not.Null);
                Assert.That(dns["limits"]?.Value<Int32>("maxServers"), Is.GreaterThan(0));
                Assert.That(dns.Value<String>("file"),       Is.EqualTo(CSMS.ConfigFile.Path));
            });

        }

        #endregion

        #region ChangingTheDNSSettingsReachesTheClientAndTheFile()

        /// <summary>
        /// Every change takes effect at once and is written down, in that order
        /// of importance: a change that was applied but not written down
        /// disappears at the next start without anybody noticing.
        /// </summary>
        [Test]
        public async Task ChangingTheDNSSettingsReachesTheClientAndTheFile()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync(
                                     "/api/v1/configuration/dns",
                                     JSONBody(
                                         new JProperty("useCache",    false),
                                         new JProperty("maxRetries",  4),
                                         new JProperty("servers",     new JArray(
                                             new JObject(
                                                 new JProperty("address",    "9.9.9.9"),
                                                 new JProperty("port",       853),
                                                 new JProperty("transport",  "TLS")
                                             )
                                         ))
                                     )
                                 );

            var answered = JObject.Parse(await response.Content.ReadAsStringAsync());
            var onDisk   = JObject.Parse(File.ReadAllText(CSMS.ConfigFile.Path));

            Assert.Multiple(() => {

                Assert.That(response.IsSuccessStatusCode, Is.True);

                // What the CSMS answers is the whole configuration as it
                // now stands, so the page shows what was taken rather than what
                // was sent.
                Assert.That(answered["settings"]?.Value<Boolean>("useCache"),   Is.False);
                Assert.That(answered["settings"]?.Value<Int32>  ("maxRetries"), Is.EqualTo(4));
                Assert.That((answered["servers"] as JArray)?.Count,             Is.EqualTo(1));

                // In the client everything below this CSMS was handed,
                // and not in a copy of it.
                Assert.That(CSMS.DNSClient.UseCache,    Is.False);
                Assert.That(CSMS.DNSClient.MaxRetries,  Is.EqualTo(4));

                // And in the file, for the next start.
                Assert.That(onDisk["dns"]?.Value<Int32>("maxRetries"), Is.EqualTo(4));

            });

        }

        #endregion

        #region WhatAChangeDoesNotMentionIsLeftAlone()

        /// <summary>
        /// A page that only offers the checkboxes must be able to send only the
        /// checkboxes without taking the name servers with it.
        /// </summary>
        [Test]
        public async Task WhatAChangeDoesNotMentionIsLeftAlone()
        {

            using var http = await SignedIn();

            var before = await GetJSON(http, "/api/v1/configuration/dns");
            var servers = (before["servers"] as JArray)?.Count ?? 0;

            await http.PutAsync("/api/v1/configuration/dns",
                                JSONBody(new JProperty("dnssecOK", true)));

            var after = await GetJSON(http, "/api/v1/configuration/dns");

            Assert.Multiple(() => {
                Assert.That(after["settings"]?.Value<Boolean>("dnssecOK"), Is.True);
                Assert.That((after["servers"] as JArray)?.Count,           Is.EqualTo(servers),
                            "A change that said nothing about the name servers took them away.");
            });

        }

        #endregion

        #region EmptyingTheNameServersIsRefused()

        /// <summary>
        /// Switching name resolution off is a thing somebody means; a list of
        /// no name servers is a thing nobody means.
        /// </summary>
        [Test]
        public async Task EmptyingTheNameServersIsRefused()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync("/api/v1/configuration/dns",
                                               JSONBody(new JProperty("servers", new JArray())));

            var error = JObject.Parse(await response.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,           Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(error.Value<String>("error"),  Does.Contain("Switch name resolution off"));
                Assert.That(CSMS.DNSClient.DNSServers.Any(), Is.True,
                            "The refused request emptied the list anyway.");
            });

        }

        #endregion

        #region ANameServerInTheLogsFormIsRefusedWithASentence()

        /// <summary>
        /// "udp://213.133.98.98:53" is how the log names a name server, and
        /// somebody copying it from there into the DNS page is told that this
        /// is not a form the list takes. The parser it goes through used to
        /// throw on it instead, out of Hermod's IPAddress.TryParse.
        /// </summary>
        [Test]
        public async Task ANameServerInTheLogsFormIsRefusedWithASentence()
        {

            using var http = await SignedIn();

            var before   = CSMS.DNSClient.DNSServers.Select(server => server.ToString()).ToArray();

            var response = await http.PutAsync("/api/v1/configuration/dns",
                                               JSONBody(new JProperty("servers", new JArray("udp://213.133.98.98:53"))));

            var body     = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  body);
                Assert.That(body,                 Does.Contain("dns.servers").And.Contain("udp://213.133.98.98:53"));
                Assert.That(CSMS.DNSClient.DNSServers.Select(server => server.ToString()),  Is.EqualTo(before),
                            "The refused request changed the name servers anyway.");
            });

        }

        #endregion

        #region SwitchingNameResolutionOffTakesTheServersAway()

        /// <summary>
        /// Off means off for everything that was handed this client, not only
        /// for the parts of the CSMS that would have remembered to check
        /// a flag first.
        /// </summary>
        [Test]
        public async Task SwitchingNameResolutionOffTakesTheServersAway()
        {

            using var http = await SignedIn();

            await http.PutAsync("/api/v1/configuration/dns",
                                JSONBody(new JProperty("enabled", false)));

            Assert.Multiple(() => {
                Assert.That(CSMS.DNSEnabled,                 Is.False);
                Assert.That(CSMS.DNSClient.DNSServers.Any(),  Is.False,
                            "Name resolution is off, but the client still holds servers to ask.");
            });

        }

        #endregion

        #region AFieldOfTheWrongKindIsRefused()

        /// <summary>
        /// Present but of the wrong kind is an error and never a silent null:
        /// somebody wrote it and deserves to be told, rather than watching the
        /// setting quietly not happen.
        /// </summary>
        [Test]
        public async Task AFieldOfTheWrongKindIsRefused()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync("/api/v1/configuration/nts",
                                               JSONBody(new JProperty("ntpPort", "onetwothree")));

            var error = JObject.Parse(await response.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,          Is.EqualTo(HttpStatusCode.BadRequest));
                // Named by its path in the document, because "must be a port
                // number" over a form with three ports on it has said nothing.
                Assert.That(error.Value<String>("error"), Does.Contain("nts.ntpPort"));
            });

        }

        #endregion


        #region TheNTSConfigurationIsReadable()

        [Test]
        public async Task TheNTSConfigurationIsReadable()
        {

            using var http = await SignedIn();

            var nts = await GetJSON(http, "/api/v1/configuration/nts");

            Assert.Multiple(() => {
                // Switched off by the fixture, so that no test reaches the
                // network - the server it would ask is still named.
                Assert.That(nts.Value<Boolean>("enabled"),                Is.False);
                Assert.That(nts["server"]?.Value<String>("hostname"),     Is.Not.Null.And.Not.Empty);
                Assert.That(nts["cookies"],                               Is.Not.Null);
                Assert.That(nts["keyExchange"],                           Is.Not.Null);
                Assert.That(nts.Value<String>("file"),                    Is.EqualTo(CSMS.ConfigFile.Path));

                // What the page draws its "Time servers" card from. A CSMS
                // nobody has configured has a group of one, and the card has
                // to have something to draw rather than nothing.
                Assert.That(nts["timeSources"],                           Is.Not.Null.And.Count.EqualTo(1));
                Assert.That(nts["timeSources"]?[0]?.Value<String>("hostname"),
                                                                          Is.EqualTo(CSMS.NTSClient.Hostname.ToString()));
                Assert.That(nts["group"]?.Value<String>("name"),          Is.EqualTo("legal"));
                Assert.That(nts["group"]?.Value<Byte>  ("minServers"),    Is.EqualTo(1));
            });

        }

        #endregion

        #region PointingTheControllerAtAnotherTimeServerReplacesTheClient()

        /// <summary>
        /// An NTS client is bound to its host at construction, and the cookies
        /// and keys it holds belong to that host and to no other - so being
        /// pointed elsewhere builds a new one rather than reconfiguring this
        /// one.
        /// </summary>
        [Test]
        public async Task PointingTheControllerAtAnotherTimeServerReplacesTheClient()
        {

            using var http = await SignedIn();

            var before = CSMS.NTSClient;

            var response = await http.PutAsync(
                                     "/api/v1/configuration/nts",
                                     JSONBody(
                                         new JProperty("hostname",   "ptbtime2.ptb.de"),
                                         new JProperty("ntsKEPort",  4460),
                                         new JProperty("ntpPort",    123)
                                     )
                                 );

            var onDisk = JObject.Parse(File.ReadAllText(CSMS.ConfigFile.Path));

            Assert.Multiple(() => {

                Assert.That(response.IsSuccessStatusCode,              Is.True);
                Assert.That(CSMS.NTSClient.Hostname.ToString(),  Does.StartWith("ptbtime2.ptb.de"));

                Assert.That(CSMS.NTSClient,                      Is.Not.SameAs(before),
                            "The host changed and the client did not, so it still holds the cookies of the old one.");

                // Written as the domain name it was parsed into, which is the
                // absolute form with the root label on the end - so this is
                // what a name looks like on its way back out of the file, and
                // not a stray character.
                Assert.That(onDisk["nts"]?.Value<String>("hostname"),
                            Is.EqualTo(CSMS.NTSClient.Hostname.ToString()));

            });

        }

        #endregion

    }

}
