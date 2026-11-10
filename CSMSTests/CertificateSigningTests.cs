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

using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.Configuration;
using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// A charging station's SignCertificate request, sent on to the EST server
    /// of a PKI, and the certificate that comes back handed to the station
    /// with CertificateSigned.
    /// </summary>
    /// <remarks>
    /// The PKI is a stand-in on the loopback address that speaks as much EST
    /// as is asked of it - simpleenroll and cacerts - and signs with a test CA
    /// that has an intermediate: what is tested is what the CSMS sends and
    /// what it passes on, and the chain it builds is the point.
    /// </remarks>
    public class CertificateSigningTests : ACSMSTests
    {

        #region Data

        private const String ThePassword = "a-password-long-enough-for-ocpp";
        private const String TheAPIKey   = "the-api-key-of-the-registrar";

        private FakeEST? est;
        private Int32    estPort;

        #endregion

        #region (override) Configuration

        protected override JObject Configuration
        {
            get
            {

                est     ??= new FakeEST();
                estPort   = est.Port;

                return new (
                    new JProperty("nts",  new JObject(new JProperty("groups", new JObject(new JProperty("legal", new JObject(new JProperty("enabled", false))))))),
                    new JProperty("ocppServer", new JObject(
                        new JProperty("enabled",           true),
                        new JProperty("address",           "127.0.0.1"),
                        new JProperty("port",              TestPorts.Free()),
                        new JProperty("securityProfiles",  new JArray(1)),
                        new JProperty("subprotocols",      new JArray("ocpp2.1", "ocpp2.0.1"))
                    )),
                    new JProperty("certificateSigning", new JObject(
                        new JProperty("chargingStationCertificate",  $"http://127.0.0.1:{estPort}/.well-known/est/stations"),
                        new JProperty("apiKey",                      TheAPIKey)
                    ))
                );

            }
        }

        [TearDown]
        public void StopTheEST()
        {
            est?.Dispose();
            est = null;
        }

        #endregion


        #region (private) A charging station speaking OCPP 2.1 JSON, and nothing else

        private async Task<ClientWebSocket> Connect(String Id)
        {

            Assert.That(CSMS.StationLogins.TrySetPassword(Id, ThePassword, null, null, out _, out var error), Is.True, error);

            var client = new ClientWebSocket();
            client.Options.AddSubProtocol("ocpp2.1");
            client.Options.SetRequestHeader("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Id}:{ThePassword}")));

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.ConnectAsync(new Uri($"ws://127.0.0.1:{CSMS.OCPPServerSettings.TCPPort}"), timeout.Token);

            return client;

        }

        private static async Task Send(ClientWebSocket Client, JArray Message)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Client.SendAsync(Encoding.UTF8.GetBytes(Message.ToString(Newtonsoft.Json.Formatting.None)), WebSocketMessageType.Text, true, timeout.Token);
        }

        /// <summary>
        /// The next OCPP message the CSMS sends.
        /// </summary>
        private static async Task<JArray> Receive(ClientWebSocket Client, TimeSpan? Within = null)
        {

            using var timeout = new CancellationTokenSource(Within ?? TimeSpan.FromSeconds(15));
            var buffer        = new Byte[64 * 1024];
            var message       = new MemoryStream();

            while (true)
            {

                var received = await Client.ReceiveAsync(buffer, timeout.Token);

                if (received.MessageType == WebSocketMessageType.Close)
                    throw new InvalidOperationException("The CSMS closed the connection.");

                message.Write(buffer, 0, received.Count);

                if (received.EndOfMessage)
                    return JArray.Parse(Encoding.UTF8.GetString(message.ToArray()));

            }

        }

        /// <summary>
        /// The CSR a charging station makes for itself, as PEM.
        /// </summary>
        private static (ECDsa Key, String CSR) KeyAndCSR(String CommonName)
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csr = new CertificateRequest($"CN={CommonName}, O=OpenChargingCloud", key, HashAlgorithmName.SHA256).CreateSigningRequestPem();
            return (key, csr);
        }

        private static JArray SignCertificate(String MessageId, String CSR, String? CertificateType = null)

            => new (2, MessageId, "SignCertificate",
                    CertificateType is null
                        ? new JObject(new JProperty("csr", CSR))
                        : new JObject(new JProperty("csr", CSR), new JProperty("certificateType", CertificateType)));

        #endregion


        #region AStationIsSignedItsCertificateByThePKI()

        [Test]
        public async Task AStationIsSignedItsCertificateByThePKI()
        {

            using var station = await Connect("cs001");
            var (key, csr)    = KeyAndCSR("cs001");

            using (key)
            {

                await Send(station, SignCertificate("m1", csr, "ChargingStationCertificate"));

                var answer = await Receive(station);

                Assert.That(answer[0]!.Value<Int32>(),                           Is.EqualTo(3), answer.ToString());
                Assert.That(answer[2]!["status"]!.Value<String>(),               Is.EqualTo("Accepted"), answer.ToString());

                var signed = await Receive(station);

                Assert.That(signed[0]!.Value<Int32>(),                           Is.EqualTo(2), signed.ToString());
                Assert.That(signed[2]!.Value<String>(),                          Is.EqualTo("CertificateSigned"));

                var chain = new X509Certificate2Collection();
                chain.ImportFromPem(signed[3]!["certificateChain"]!.Value<String>()!);

                await Send(station, new JArray(3, signed[1]!.Value<String>()!, new JObject(new JProperty("status", "Accepted"))));

                using var leaf      = chain[0];
                using var publicKey = leaf.GetECDsaPublicKey()!;

                Assert.Multiple(() => {
                    Assert.That(signed[3]!["certificateType"]!.Value<String>(),      Is.EqualTo("ChargingStationCertificate"));
                    Assert.That(leaf.GetNameInfo(X509NameType.SimpleName, false),    Is.EqualTo("cs001"));
                    Assert.That(publicKey.ExportSubjectPublicKeyInfo(),              Is.EqualTo(key.ExportSubjectPublicKeyInfo()), "for the station's own key");
                    Assert.That(chain.Count,                                         Is.EqualTo(2), "the certificate and its intermediate, without the root");
                    Assert.That(chain[1].Thumbprint,                                 Is.EqualTo(est!.CA.Intermediate!.Thumbprint));
                    Assert.That(est.APIKeys,                                         Has.Some.EqualTo(TheAPIKey), "signed in to the PKI with its API key");
                });

                await WaitFor(() => CSMS.CertificateSignings.FirstOrDefault()?.Outcome == "signed", "the CSMS did not note the certificate as taken");

                var entry = CSMS.CertificateSignings.First();

                Assert.Multiple(() => {
                    Assert.That(entry.Station,                                       Is.EqualTo("cs001"));
                    Assert.That(entry.Certificate,                                   Is.EqualTo(leaf.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant()));
                });

            }

        }

        #endregion

        #region ACSRForAnotherStationIsRejected()

        [Test]
        public async Task ACSRForAnotherStationIsRejected()
        {

            using var station = await Connect("cs001");
            var (key, csr)    = KeyAndCSR("cs002");

            using (key)
            {

                await Send(station, SignCertificate("m1", csr));

                var answer = await Receive(station);

                Assert.Multiple(() => {
                    Assert.That(answer[2]!["status"]!.Value<String>(),                        Is.EqualTo("Rejected"), answer.ToString());
                    Assert.That(answer[2]!["statusInfo"]!["additionalInfo"]!.Value<String>(), Does.Contain("cs002"));
                    Assert.That(est!.Requests,                                                Is.Empty, "nothing went to the PKI");
                    Assert.That(CSMS.CertificateSignings.First().Outcome,                     Is.EqualTo("rejected"));
                });

            }

        }

        #endregion

        #region WhatNoPKISignsIsRejected()

        [Test]
        public async Task WhatNoPKISignsIsRejected()
        {

            using var station = await Connect("cs001");
            var (key, csr)    = KeyAndCSR("DE*OCC*E1234567*1");

            using (key)
            {

                await Send(station, SignCertificate("m1", csr, "V2GCertificate"));
                var noPKI   = await Receive(station);

                await Send(station, SignCertificate("m2", "-----BEGIN CERTIFICATE REQUEST-----\nbm90IGEgY3Ny\n-----END CERTIFICATE REQUEST-----\n"));
                var noCSR   = await Receive(station);

                Assert.Multiple(() => {
                    Assert.That(noPKI[2]!["status"]!.Value<String>(),                     Is.EqualTo("Rejected"));
                    Assert.That(noPKI[2]!["statusInfo"]!["reasonCode"]!.Value<String>(),  Is.EqualTo("Unsupported"));
                    Assert.That(noCSR[2]!["status"]!.Value<String>(),                     Is.EqualTo("Rejected"));
                    Assert.That(noCSR[2]!["statusInfo"]!["reasonCode"]!.Value<String>(),  Is.EqualTo("InvalidCSR"));
                    Assert.That(est!.Requests,                                            Is.Empty);
                });

            }

        }

        #endregion

        #region WhatThePKIRefusesIsNoted()

        [Test]
        public async Task WhatThePKIRefusesIsNoted()
        {

            est!.Refuse = "The CA of EST signs nothing: It is revoked.";

            using var station = await Connect("cs001");
            var (key, csr)    = KeyAndCSR("cs001");

            using (key)
            {

                await Send(station, SignCertificate("m1", csr));

                var answer = await Receive(station);

                Assert.That(answer[2]!["status"]!.Value<String>(), Is.EqualTo("Accepted"), "the station is answered before the PKI is asked");

                await WaitFor(() => CSMS.CertificateSignings.FirstOrDefault()?.Outcome == "failed", "the refusal of the PKI was not noted");

                Assert.That(CSMS.CertificateSignings.First().Detail, Does.Contain("It is revoked"));

            }

        }

        #endregion

        #region TheSettingsAreShownWithoutTheAPIKey()

        [Test]
        public async Task TheSettingsAreShownWithoutTheAPIKey()
        {

            using var browser = await SignedIn();

            var shown  = JObject.Parse(await browser.GetStringAsync("api/v1/configuration/certificate-signing"));

            using var plainHTTP = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                         new StringContent("""{ "v2gCertificate": "http://pki.example.org/.well-known/est/secc" }""", Encoding.UTF8, "application/json"));

            using var put = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                   new StringContent("""{ "v2gCertificate": "https://pki.example.org/.well-known/est/secc", "chargingStationCertificate": null }""", Encoding.UTF8, "application/json"));

            var changed = JObject.Parse(await put.Content.ReadAsStringAsync());
            var file    = JObject.Parse(File.ReadAllText(Path.Combine(Directory, WWCPConfigFile.DefaultFileName)))[CertificateSigningConfiguration.SectionName]!;

            Assert.Multiple(() => {
                Assert.That(shown["apiKey"]!.Value<Boolean>(),                        Is.True, "there is one, and it is not shown");
                Assert.That(shown.ToString(),                                         Does.Not.Contain(TheAPIKey));
                Assert.That(plainHTTP.StatusCode,                                     Is.EqualTo(HttpStatusCode.BadRequest), "no API key over plain HTTP to somewhere else");
                Assert.That(put.StatusCode,                                           Is.EqualTo(HttpStatusCode.OK), changed.ToString());
                Assert.That(changed["chargingStationCertificate"]!.Type,              Is.EqualTo(JTokenType.Null), "removed");
                Assert.That(changed["v2gCertificate"]!.Value<String>(),               Is.EqualTo("https://pki.example.org/.well-known/est/secc"));
                Assert.That(file["apiKey"]!.Value<String>(),                          Is.EqualTo(TheAPIKey), "kept where it was not named");
            });

        }

        #endregion


        #region AStationWhoseCertificateRunsOutIsAskedForANewOneAfterItsBootNotification()

        [Test]
        public async Task AStationWhoseCertificateRunsOutIsAskedForANewOneAfterItsBootNotification()
        {

            // A certificate of a year, ten days of which are left.
            est!.ValidFor     = TimeSpan.FromDays(10);
            est.IssuedAgo     = TimeSpan.FromDays(355);

            using var station = await Connect("cs001");

            await SignedACertificate(station, "cs001");

            var known = CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate");

            Assert.That(known,         Is.Not.Null, "the certificate the station took is known");
            Assert.That(known!.Source, Is.EqualTo("signed"));

            await Booted(station, "b1");

            var trigger = await Receive(station);

            Assert.Multiple(() => {
                Assert.That(trigger[0]!.Value<Int32>(),                         Is.EqualTo(2), trigger.ToString());
                Assert.That(trigger[2]!.Value<String>(),                        Is.EqualTo("TriggerMessage"));
                Assert.That(trigger[3]!["requestedMessage"]!.Value<String>(),   Is.EqualTo("SignChargingStationCertificate"));
            });

            await Send(station, new JArray(3, trigger[1]!.Value<String>()!, new JObject(new JProperty("status", "Accepted"))));

            await WaitFor(() => CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate")?.RenewalAnswer == "Accepted",
                          "what the station answered was not noted");

            // Looked at again the same day: asked once a day, not at every
            // start and every check.
            Assert.That(await CSMS.RenewDueCertificates("cs001"), Is.EqualTo(0), "asked again within the day");

            // And the CSR it sends goes the way every other does: the new
            // certificate is the one known now, and not due.
            est.ValidFor  = TimeSpan.FromDays(365);
            est.IssuedAgo = TimeSpan.FromMinutes(5);

            await SignedACertificate(station, "cs001", "m2");

            Assert.That(CSMS.IsDue(CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate")!), Is.False);

            await Booted(station, "b2");

            Assert.That(async () => await Receive(station, TimeSpan.FromSeconds(2)), Throws.InstanceOf<OperationCanceledException>(),
                        "asked for the certificate it was just signed");

        }

        #endregion

        #region ACertificateThatHoldsLongIsNotRenewed()

        [Test]
        public async Task ACertificateThatHoldsLongIsNotRenewed()
        {

            using var station = await Connect("cs001");

            await SignedACertificate(station, "cs001");
            await Booted(station, "b1");

            Assert.That(async () => await Receive(station, TimeSpan.FromSeconds(2)), Throws.InstanceOf<OperationCanceledException>(),
                        "asked for a certificate that holds for a year");

            Assert.That(await CSMS.RenewDueCertificates(), Is.EqualTo(0));

        }

        #endregion

        #region ACertificateThatHoldsLessThanTheDaysConfiguredIsRenewedHalfway()

        /// <summary>
        /// A PKI that signs for ten days, with the thirty days before of the
        /// default: the new certificate would be due the day it was signed, and
        /// the station asked every day. It is renewed halfway instead.
        /// </summary>
        [Test]
        public async Task ACertificateThatHoldsLessThanTheDaysConfiguredIsRenewedHalfway()
        {

            est!.ValidFor     = TimeSpan.FromDays(10);

            using var station = await Connect("cs001");
            using var browser = await SignedIn();

            await SignedACertificate(station, "cs001");
            await Booted(station, "b1");

            Assert.That(async () => await Receive(station, TimeSpan.FromSeconds(2)), Throws.InstanceOf<OperationCanceledException>(),
                        "asked for the certificate it was just signed");

            var known       = CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate")!;
            var shown       = JObject.Parse(await browser.GetStringAsync("api/v1/configuration/certificate-signing"));
            var certificate = shown["certificates"]!.Single(one => one["station"]!.Value<String>() == "cs001");

            Assert.Multiple(() => {
                Assert.That(known.NotBefore,                            Is.Not.Null, "its first day is kept");
                Assert.That(CSMS.IsHalfway(known),                      Is.True);
                Assert.That(CSMS.IsDue(known),                          Is.False);
                Assert.That(CSMS.RenewsFrom(known),                     Is.EqualTo(known.NotAfter - (known.NotAfter - known.NotBefore!.Value) / 2));
                Assert.That(certificate["halfway"]!.Value<Boolean>(),   Is.True);
                Assert.That(certificate["renewsFrom"]!.Type,            Is.Not.EqualTo(JTokenType.Null));
            });

            // Halfway through, it is.
            var later = known with { NotBefore = known.NotBefore!.Value.AddDays(-6), NotAfter = known.NotAfter.AddDays(-6) };

            Assert.That(CSMS.IsDue(later), Is.True, "past half of its life");

            // Of a certificate whose first day is not known, as of one noted
            // before it was kept, only the days configured count.
            Assert.That(CSMS.IsDue(known with { NotBefore = null }), Is.True);

        }

        #endregion

        #region ACertificateIsForgotten()

        /// <summary>
        /// Forgotten by hand, and with its station: not renewed any more.
        /// </summary>
        [Test]
        public async Task ACertificateIsForgotten()
        {

            using var station = await Connect("cs001");
            using var browser = await SignedIn();

            await SignedACertificate(station, "cs001");

            CSMS.StationCertificates.Note("cs001", "V2GCertificate",             "ee", DateTimeOffset.UtcNow.AddDays(100), "signed", DateTimeOffset.UtcNow);
            CSMS.StationCertificates.Note("cs002", "ChargingStationCertificate", "ff", DateTimeOffset.UtcNow.AddDays(100), "signed", DateTimeOffset.UtcNow);

            using var forgotten = await browser.DeleteAsync("api/v1/configuration/certificate-signing/certificates/cs001/V2GCertificate");
            using var unknown   = await browser.DeleteAsync("api/v1/configuration/certificate-signing/certificates/cs001/V2GCertificate");
            var shown           = JObject.Parse(await forgotten.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(forgotten.StatusCode,                                                   Is.EqualTo(HttpStatusCode.OK), shown.ToString());
                Assert.That(unknown.StatusCode,                                                     Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(shown["certificates"]!.Count(),                                         Is.EqualTo(2));
                Assert.That(CSMS.StationCertificates.Get("cs001", "V2GCertificate"),                Is.Null);
                Assert.That(CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate"),    Is.Not.Null, "only the one named");
            });

            // The file says so too: a restart does not bring it back.
            var again = new StationCertificates(CSMS.StationCertificates.Path);
            again.Load();

            Assert.That(again.Get("cs001", "V2GCertificate"), Is.Null);

            // The station removed: its certificates with it, and no other's.
            using var removed = await browser.DeleteAsync("api/v1/configuration/ocpp-server/stations/cs001");

            Assert.Multiple(() => {
                Assert.That(removed.StatusCode,                                                     Is.EqualTo(HttpStatusCode.OK));
                Assert.That(CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate"),    Is.Null);
                Assert.That(CSMS.StationCertificates.Get("cs002", "ChargingStationCertificate"),    Is.Not.Null);
            });

        }

        #endregion

        #region AStationIsAskedByHandToRenew()

        [Test]
        public async Task AStationIsAskedByHandToRenew()
        {

            using var station = await Connect("cs001");
            using var browser = await SignedIn();

            await SignedACertificate(station, "cs001");

            var asking  = browser.PostAsync("api/v1/configuration/certificate-signing/renew",
                                            JSONBody(new JProperty("station", "cs001"), new JProperty("certificateType", "ChargingStationCertificate")));

            var trigger = await Receive(station);

            Assert.That(trigger[3]!["requestedMessage"]!.Value<String>(), Is.EqualTo("SignChargingStationCertificate"), trigger.ToString());

            await Send(station, new JArray(3, trigger[1]!.Value<String>()!, new JObject(new JProperty("status", "Rejected"))));

            using var asked   = await asking;
            var answer        = JObject.Parse(await asked.Content.ReadAsStringAsync());

            using var nobody  = await browser.PostAsync("api/v1/configuration/certificate-signing/renew",
                                                        JSONBody(new JProperty("station", "cs999"), new JProperty("certificateType", "ChargingStationCertificate")));

            using var noV2G   = await browser.PostAsync("api/v1/configuration/certificate-signing/renew",
                                                        JSONBody(new JProperty("station", "cs001"), new JProperty("certificateType", "V2GCertificate")));

            var shown         = JObject.Parse(await browser.GetStringAsync("api/v1/configuration/certificate-signing"));
            var certificate   = shown["certificates"]!.Single(one => one["station"]!.Value<String>() == "cs001");

            Assert.Multiple(() => {
                Assert.That(asked.StatusCode,                                 Is.EqualTo(HttpStatusCode.OK), answer.ToString());
                Assert.That(answer["answer"]!.Value<String>(),                Is.EqualTo("Rejected"));
                Assert.That(nobody.StatusCode,                                Is.EqualTo(HttpStatusCode.Conflict), "not connected");
                Assert.That(noV2G.StatusCode,                                 Is.EqualTo(HttpStatusCode.BadRequest), "no PKI signs it");
                Assert.That(shown["renewDaysBefore"]!.Value<Int32>(),         Is.EqualTo(CertificateSigningConfiguration.DefaultRenewDaysBefore));
                Assert.That(certificate["source"]!.Value<String>(),           Is.EqualTo("signed"));
                Assert.That(certificate["connected"]!.Value<Boolean>(),       Is.True);
                Assert.That(certificate["due"]!.Value<Boolean>(),             Is.False);
                Assert.That(certificate["renewalAnswer"]!.Value<String>(),    Is.EqualTo("Rejected"));
            });

        }

        #endregion

        #region HowLongBeforeIsSaidInDays()

        [Test]
        public async Task HowLongBeforeIsSaidInDays()
        {

            using var browser = await SignedIn();

            using var tooLong = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                       new StringContent("""{ "renewDaysBefore": 1000 }""", Encoding.UTF8, "application/json"));

            using var never   = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                       new StringContent("""{ "renewDaysBefore": 0 }""", Encoding.UTF8, "application/json"));

            var file = JObject.Parse(File.ReadAllText(Path.Combine(Directory, WWCPConfigFile.DefaultFileName)))[CertificateSigningConfiguration.SectionName]!;

            Assert.Multiple(() => {
                Assert.That(tooLong.StatusCode,                      Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(never.StatusCode,                        Is.EqualTo(HttpStatusCode.OK));
                Assert.That(file["renewDaysBefore"]!.Value<Int32>(), Is.EqualTo(0));
                Assert.That(CSMS.CertificateSigning.RenewBefore,     Is.EqualTo(TimeSpan.Zero));
                Assert.That(CSMS.IsDue(new StationCertificate("cs001", "ChargingStationCertificate", "ab", DateTimeOffset.UtcNow.AddDays(1), "signed", DateTimeOffset.UtcNow)),
                            Is.False, "never renewed");
            });

        }

        #endregion

        #region TheCertificatesOfTheStationsAreKeptInTheirFile()

        [Test]
        public void TheCertificatesOfTheStationsAreKeptInTheirFile()
        {

            var path   = Path.Combine(Directory, "kept", StationCertificates.DefaultFileName);
            var now    = DateTimeOffset.UtcNow;

            var first  = new StationCertificates(path);
            first.Load();

            Assert.Multiple(() => {
                Assert.That(first.Note("cs001", "ChargingStationCertificate", "aa", now.AddDays(100), "signed",    now), Is.True);
                Assert.That(first.Note("cs001", "ChargingStationCertificate", "bb", now.AddDays(10),  "presented", now), Is.False, "the later certificate wins");
                Assert.That(first.Note("cs001", "V2GCertificate",             "cc", now.AddDays(20),  "signed",    now), Is.True);
            });

            first.NoteAsked("cs001", "V2GCertificate", now, "NotImplemented");

            var second = new StationCertificates(path);
            second.Load();

            Assert.Multiple(() => {
                Assert.That(second.All.Count,                                                   Is.EqualTo(2));
                Assert.That(second.Get("cs001", "ChargingStationCertificate")!.Fingerprint,     Is.EqualTo("aa"));
                Assert.That(second.Get("cs001", "V2GCertificate")!.RenewalAnswer,               Is.EqualTo("NotImplemented"));
            });

            File.WriteAllText(path, "{ not json");

            var notices = new List<String>();
            var third   = new StationCertificates(path);
            third.OnNotice += (level, message) => notices.Add(message);
            third.Load();

            Assert.Multiple(() => {
                Assert.That(third.All,                          Is.Empty);
                Assert.That(File.Exists(path + ".unreadable"),  Is.True, "put aside, not overwritten");
                Assert.That(notices,                            Has.Some.Contains("could not be read"));
            });

        }

        #endregion


        #region AStationAsksWhetherACertificateIsRevoked()

        /// <summary>
        /// A station's GetCertificateStatus, sent on to the OCSP responder of
        /// the PKI - on the host of its EST server - and its answer handed
        /// back as it came: of a certificate revoked, and of one that is not.
        /// </summary>
        [Test]
        public async Task AStationAsksWhetherACertificateIsRevoked()
        {

            using var station = await Connect("cs001");
            using var browser = await SignedIn();

            est!.Revoked.TryAdd("1a2b3c", 0);

            var responder = $"http://127.0.0.1:{estPort}/api/v1/pki/ocsp";

            await Send(station, GetCertificateStatus("s1", "1A2B3C", responder));
            var revoked = await Receive(station);

            await Send(station, GetCertificateStatus("s2", "0FF", responder));
            var good    = await Receive(station);

            var der     = Convert.FromBase64String(revoked[2]!["ocspResult"]!.Value<String>()!);
            var shown   = JObject.Parse(await browser.GetStringAsync("api/v1/configuration/certificate-signing"));

            Assert.Multiple(() => {

                Assert.That(revoked[0]!.Value<Int32>(),                     Is.EqualTo(3), revoked.ToString());
                Assert.That(revoked[2]!["status"]!.Value<String>(),         Is.EqualTo("Accepted"));
                Assert.That(OCSPMessages.TryRead(der, "1a2b3c", out var read), Is.True, "what the station is handed is the OCSP response");
                Assert.That(read!.CertificateStatus,                        Is.EqualTo("revoked"));
                Assert.That(good[2]!["status"]!.Value<String>(),            Is.EqualTo("Accepted"));

                Assert.That(est.OCSPRequests.Count,                         Is.EqualTo(2), "asked of the responder");

                Assert.That(CSMS.CertificateStatuses.Select(entry => entry.Outcome),      Is.EqualTo(new[] { "good", "revoked" }), "the newest first");
                Assert.That(CSMS.CertificateStatuses[1].NextUpdate,                       Is.Not.Null);
                Assert.That(shown["statusRequests"]!.Count(),                             Is.EqualTo(2));
                Assert.That(shown["statusRequests"]![1]!["serialNumber"]!.Value<String>(), Is.EqualTo("1A2B3C"));

            });

        }

        #endregion

        #region AResponderNoneToldOfIsNotAsked()

        /// <summary>
        /// The responder is a station's word: one on another host than the
        /// EST server, and none named, is not asked - nor a request that is no
        /// OCSP request - and the station is told Failed.
        /// </summary>
        [Test]
        public async Task AResponderNoneToldOfIsNotAsked()
        {

            using var station = await Connect("cs001");

            await Send(station, GetCertificateStatus("s1", "1A2B3C", $"http://127.0.0.2:{estPort}/api/v1/pki/ocsp"));
            var elsewhere = await Receive(station);

            await Send(station, GetCertificateStatus("s2", "1A2B3C", $"http://127.0.0.1:{estPort}/api/v1/pki/ocsp", NameHash: "abcd"));
            var shortHash = await Receive(station);

            est!.OCSPStatus = (Int32) FakeEST.OCSPResponseStatus.TryLater;

            await Send(station, GetCertificateStatus("s3", "1A2B3C", $"http://127.0.0.1:{estPort}/api/v1/pki/ocsp"));
            var later     = await Receive(station);

            Assert.Multiple(() => {
                Assert.That(elsewhere[2]!["status"]!.Value<String>(),                  Is.EqualTo("Failed"), elsewhere.ToString());
                Assert.That(elsewhere[2]!["statusInfo"]!["reasonCode"]!.Value<String>(), Is.EqualTo("UnknownResponder"));
                Assert.That(shortHash[2]!["status"]!.Value<String>(),                  Is.EqualTo("Failed"));
                Assert.That(later[2]!["status"]!.Value<String>(),                      Is.EqualTo("Failed"));
                Assert.That(est.OCSPRequests.Count,                                    Is.EqualTo(1), "only the request that could be sent was sent");
                Assert.That(CSMS.CertificateStatuses.Select(entry => entry.Outcome),   Is.EqualTo(new[] { "failed", "refused", "refused" }));
                Assert.That(CSMS.CertificateStatuses[0].Detail,                        Does.Contain("tryLater"));
            });

        }

        #endregion

        #region TheOCSPRespondersAreNamed()

        /// <summary>
        /// The responders beside the EST host, as the API takes them - and
        /// which are asked: one named, below its path; one on the host of an
        /// EST server, at its port and those of HTTP and HTTPS.
        /// </summary>
        [Test]
        public async Task TheOCSPRespondersAreNamed()
        {

            using var browser = await SignedIn();

            using var notAList = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                        new StringContent("""{ "ocspResponders": "http://ocsp.example.com/" }""", Encoding.UTF8, "application/json"));

            using var notAURL  = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                        new StringContent("""{ "ocspResponders": [ "ftp://ocsp.example.com/" ] }""", Encoding.UTF8, "application/json"));

            using var named    = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                        new StringContent("""{ "ocspResponders": [ "http://ocsp.example.com/a" ] }""", Encoding.UTF8, "application/json"));

            var shown          = JObject.Parse(await named.Content.ReadAsStringAsync());
            var file           = JObject.Parse(File.ReadAllText(Path.Combine(Directory, WWCPConfigFile.DefaultFileName)))[CertificateSigningConfiguration.SectionName]!;
            var signing        = CSMS.CertificateSigning;

            Assert.Multiple(() => {

                Assert.That(notAList.StatusCode,                              Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(notAURL.StatusCode,                               Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(named.StatusCode,                                 Is.EqualTo(HttpStatusCode.OK), shown.ToString());
                Assert.That(shown["ocspResponders"]![0]!.Value<String>(),     Is.EqualTo("http://ocsp.example.com/a"));
                Assert.That(file["ocspResponders"]![0]!.Value<String>(),      Is.EqualTo("http://ocsp.example.com/a"));
                Assert.That(file["apiKey"]!.Value<String>(),                  Is.EqualTo(TheAPIKey), "what was not named stays");

                Assert.That(signing.MayAsk(new Uri("http://ocsp.example.com/a")),                  Is.True);
                Assert.That(signing.MayAsk(new Uri("http://ocsp.example.com/a/b")),                Is.True);
                Assert.That(signing.MayAsk(new Uri("http://ocsp.example.com/ab")),                 Is.False, "not below its path");
                Assert.That(signing.MayAsk(new Uri("https://ocsp.example.com/a")),                 Is.False, "not at another scheme");
                Assert.That(signing.MayAsk(new Uri("http://user@ocsp.example.com/a")),             Is.False);
                Assert.That(signing.MayAsk(new Uri($"http://127.0.0.1:{estPort}/anything")),       Is.True,  "on the host of the EST server");
                Assert.That(signing.MayAsk(new Uri("http://127.0.0.1/ocsp")),                      Is.True,  "at the port of HTTP");
                Assert.That(signing.MayAsk(new Uri("http://127.0.0.1:6379/")),                     Is.False, "at any other port");
                Assert.That(signing.MayAsk(new Uri("http://127.0.0.2/ocsp")),                      Is.False);

            });

            using var none = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                    new StringContent("""{ "ocspResponders": null }""", Encoding.UTF8, "application/json"));

            Assert.That(CSMS.CertificateSigning.MayAsk(new Uri("http://ocsp.example.com/a")), Is.False, "taken away");

        }

        #endregion


        #region ARevokedCertificateOfAStationIsReplaced()

        /// <summary>
        /// A station asks about its own certificate, and the responder says it
        /// is revoked: the station is asked for a new one at once, and not when
        /// the old one would run out.
        /// </summary>
        [Test]
        public async Task ARevokedCertificateOfAStationIsReplaced()
        {

            using var station = await Connect("cs001");

            await SignedACertificate(station, "cs001");

            var serial = CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate")!.SerialNumber;

            Assert.That(serial, Is.Not.Null, "its serial number is kept");

            est!.Revoked.TryAdd(serial!.TrimStart('0').ToLowerInvariant(), 0);

            await Send(station, GetCertificateStatus("s1", serial, $"http://127.0.0.1:{estPort}/api/v1/pki/ocsp"));

            // The answer and the TriggerMessage, in whichever order they come.
            var first   = await Receive(station);
            var second  = await Receive(station);
            var answer  = first[0]!.Value<Int32>() == 3 ? first  : second;
            var trigger = first[0]!.Value<Int32>() == 3 ? second : first;

            Assert.Multiple(() => {
                Assert.That(answer[2]!["status"]!.Value<String>(),                Is.EqualTo("Accepted"), answer.ToString());
                Assert.That(trigger[2]!.Value<String>(),                          Is.EqualTo("TriggerMessage"), trigger.ToString());
                Assert.That(trigger[3]!["requestedMessage"]!.Value<String>(),     Is.EqualTo("SignChargingStationCertificate"));
            });

            await Send(station, new JArray(3, trigger[1]!.Value<String>()!, new JObject(new JProperty("status", "Accepted"))));

            await WaitFor(() => CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate")?.RenewalAnswer == "Accepted",
                          "what the station answered was not noted");

        }

        #endregion

        #region TheRootsAreTakenFromThePKI()

        /// <summary>
        /// The CAs the EST servers name that signed themselves: the one above
        /// the V2G certificates added as the V2G root - once.
        /// </summary>
        [Test]
        public async Task TheRootsAreTakenFromThePKI()
        {

            using var browser = await SignedIn();

            using var v2g     = await browser.PutAsync("api/v1/configuration/certificate-signing",
                                                       new StringContent($$"""{ "v2gCertificate": "http://127.0.0.1:{{estPort}}/.well-known/est/secc" }""", Encoding.UTF8, "application/json"));

            using var taken   = await browser.PostAsync("api/v1/configuration/station-roots/from-pki", JSONBody());
            var shown         = JObject.Parse(await taken.Content.ReadAsStringAsync());

            using var again   = await browser.PostAsync("api/v1/configuration/station-roots/from-pki", JSONBody());
            var shownAgain    = JObject.Parse(await again.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(v2g.StatusCode,                                             Is.EqualTo(HttpStatusCode.OK));
                Assert.That(taken.StatusCode,                                           Is.EqualTo(HttpStatusCode.OK), shown.ToString());
                Assert.That(shown["added"]!.Count(),                                    Is.EqualTo(1), shown.ToString());
                Assert.That(shown["added"]![0]!["certificateType"]!.Value<String>(),    Is.EqualTo("V2GRootCertificate"));
                Assert.That(shown["added"]![0]!["id"]!.Value<String>(),                 Is.EqualTo(est!.CA.Certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant()));
                Assert.That(shownAgain["added"]!.Count(),                               Is.EqualTo(0), "not twice");
                Assert.That(CSMS.StationRoots.All.Count,                                Is.EqualTo(1));
            });

        }

        #endregion


        #region (private) GetCertificateStatus(MessageId, SerialNumber, Responder, NameHash = null)

        /// <summary>
        /// A station asking whether a certificate below the intermediate of the
        /// PKI is revoked.
        /// </summary>
        private JArray GetCertificateStatus(String   MessageId,
                                            String   SerialNumber,
                                            String   Responder,
                                            String?  NameHash   = null)

            => new (2, MessageId, "GetCertificateStatus",
                    new JObject(
                        new JProperty("ocspRequestData", new JObject(
                            new JProperty("hashAlgorithm",   "SHA256"),
                            new JProperty("issuerNameHash",  NameHash ?? Convert.ToHexString(SHA256.HashData(est!.CA.Intermediate!.SubjectName.RawData)).ToLowerInvariant()),
                            new JProperty("issuerKeyHash",   Convert.ToHexString(SHA256.HashData(est!.CA.Intermediate!.PublicKey.EncodedKeyValue.RawData)).ToLowerInvariant()),
                            new JProperty("serialNumber",    SerialNumber),
                            new JProperty("responderURL",    Responder)
                        ))
                    ));

        #endregion

        #region (private) SignedACertificate(Station, Id, MessageId = "m1") / Booted(Station, MessageId)

        /// <summary>
        /// A station asks for its certificate, and takes it: the one the CSMS
        /// knows of now.
        /// </summary>
        private async Task SignedACertificate(ClientWebSocket Station, String Id, String MessageId = "m1")
        {

            var (key, csr) = KeyAndCSR(Id);

            using (key)
            {

                await Send(Station, SignCertificate(MessageId, csr, "ChargingStationCertificate"));

                var answer = await Receive(Station);
                Assert.That(answer[2]!["status"]!.Value<String>(), Is.EqualTo("Accepted"), answer.ToString());

                var signed = await Receive(Station);
                Assert.That(signed[2]!.Value<String>(), Is.EqualTo("CertificateSigned"), signed.ToString());

                var chain  = new X509Certificate2Collection();
                chain.ImportFromPem(signed[3]!["certificateChain"]!.Value<String>()!);

                var fingerprint = chain[0].GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();

                await Send(Station, new JArray(3, signed[1]!.Value<String>()!, new JObject(new JProperty("status", "Accepted"))));

                await WaitFor(() => CSMS.StationCertificates.Get(Id, "ChargingStationCertificate")?.Fingerprint == fingerprint,
                              "the certificate the station took is not the one known");

                foreach (var one in chain)
                    one.Dispose();

            }

        }

        /// <summary>
        /// A station says it has started, and is accepted.
        /// </summary>
        private static async Task Booted(ClientWebSocket Station, String MessageId)
        {

            await Send(Station, new JArray(2, MessageId, "BootNotification",
                                           new JObject(
                                               new JProperty("chargingStation", new JObject(new JProperty("model", "Test"), new JProperty("vendorName", "OpenChargingCloud"))),
                                               new JProperty("reason",          "PowerUp")
                                           )));

            var answer = await Receive(Station);

            Assert.That(answer[0]!.Value<Int32>(),             Is.EqualTo(3), answer.ToString());
            Assert.That(answer[2]!["status"]!.Value<String>(), Is.EqualTo("Accepted"), answer.ToString());

        }

        #endregion


        #region (private) WaitFor(Condition, Why)

        private static async Task WaitFor(Func<Boolean> Condition, String Why)
        {

            var until = DateTime.UtcNow.AddSeconds(15);

            while (!Condition())
            {
                if (DateTime.UtcNow > until)
                    Assert.Fail(Why);
                await Task.Delay(50);
            }

        }

        #endregion


        #region (private class) FakeEST

        /// <summary>
        /// As much of an EST server as the CSMS asks of it, on the loopback
        /// address: "simpleenroll" signs with a test CA that has an
        /// intermediate, and "cacerts" hands out the intermediate and the root.
        /// </summary>
        private sealed class FakeEST : IDisposable
        {

            private readonly TcpListener              listener;
            private readonly CancellationTokenSource  stop = new ();

            public TestCA                             CA        { get; } = TestCA.Create("EST Test CA", WithIntermediate: true);
            public Int32                              Port      { get; }
            public ConcurrentQueue<String>            Requests  { get; } = new ();
            public ConcurrentQueue<String>            APIKeys   { get; } = new ();
            public String?                            Refuse    { get; set; }
            public TimeSpan                           ValidFor  { get; set; } = TimeSpan.FromDays(365);
            public TimeSpan                           IssuedAgo { get; set; } = TimeSpan.FromMinutes(5);

            /// <summary>
            /// The OCSP requests it was sent, as DER; the serial numbers it says
            /// are revoked, in lower case hexadecimal; and the responseStatus it
            /// answers with, where it is not successful.
            /// </summary>
            public ConcurrentQueue<Byte[]>            OCSPRequests   { get; } = new ();
            public ConcurrentDictionary<String, Byte> Revoked        { get; } = new ();
            public Int32?                             OCSPStatus     { get; set; }

            public FakeEST()
            {
                listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                Port     = ((IPEndPoint) listener.LocalEndpoint).Port;
                _        = Task.Run(Serve);
            }

            private async Task Serve()
            {
                while (!stop.IsCancellationRequested)
                {
                    TcpClient client;
                    try { client = await listener.AcceptTcpClientAsync(stop.Token); }
                    catch (Exception) { return; }
                    _ = Task.Run(() => Answer(client));
                }
            }

            private async Task Answer(TcpClient Client)
            {

                using var client = Client;
                var stream       = client.GetStream();
                var head         = new StringBuilder();

                while (!head.ToString().EndsWith("\r\n\r\n"))
                {
                    var one = stream.ReadByte();
                    if (one < 0) return;
                    head.Append((Char) one);
                }

                var lines   = head.ToString().Split("\r\n");
                var request = lines[0].Split(' ');
                var headers = lines.Skip(1).Where(line => line.Contains(':')).ToDictionary(line => line.Split(':', 2)[0].Trim().ToLowerInvariant(), line => line.Split(':', 2)[1].Trim());
                var body    = new Byte[headers.TryGetValue("content-length", out var length) ? Int32.Parse(length) : 0];

                for (var read = 0; read < body.Length;)
                    read += await stream.ReadAsync(body.AsMemory(read));

                Requests.Enqueue($"{request[0]} {request[1]}");

                if (headers.TryGetValue("api-key", out var apiKey))
                    APIKeys.Enqueue(apiKey);

                String   status;
                String   contentType = "application/pkcs7-mime; smime-type=certs-only";
                String   answer      = "";
                Byte[]?  binary      = null;

                if (request[0] == "POST" && request[1].EndsWith("/ocsp"))
                {
                    OCSPRequests.Enqueue(body);
                    status      = "200 OK";
                    contentType = "application/ocsp-response";
                    binary      = OCSPResponse(body);
                }
                else if (request[0] == "POST" && request[1].EndsWith("/simpleenroll"))
                {
                    if (Refuse is not null)
                    {
                        status      = "503 Service Unavailable";
                        contentType = "text/plain";
                        answer      = Refuse;
                    }
                    else
                    {
                        var csr     = PemEncoding.WriteString("CERTIFICATE REQUEST", Convert.FromBase64String(Encoding.ASCII.GetString(body)));
                        using var certificate = CA.Sign(csr, DateTimeOffset.UtcNow - IssuedAgo, DateTimeOffset.UtcNow.Add(ValidFor), ClientAuthentication: true);
                        status      = "200 OK";
                        answer      = Convert.ToBase64String(CertsOnly(certificate));
                    }
                }
                else if (request[0] == "GET" && request[1].EndsWith("/cacerts"))
                {
                    status = "200 OK";
                    answer = Convert.ToBase64String(CertsOnly(CA.Intermediate!, CA.Certificate));
                }
                else
                {
                    status      = "404 Not Found";
                    contentType = "text/plain";
                    answer      = "no such thing";
                }

                var bytes = binary ?? Encoding.ASCII.GetBytes(answer);
                var reply = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: {contentType}\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");

                await stream.WriteAsync(reply);
                await stream.WriteAsync(bytes);

            }

            /// <summary>
            /// The answer to an OCSP request of one certificate, RFC 6960: good,
            /// or revoked where its serial number is in Revoked - signed with
            /// nothing anybody could check, which is not what is tested.
            /// </summary>
            private Byte[] OCSPResponse(Byte[] Request)
            {

                var writer = new AsnWriter(AsnEncodingRules.DER);

                if (OCSPStatus is Int32 failed)
                {
                    using (writer.PushSequence())
                        writer.WriteEnumeratedValue((OCSPResponseStatus) failed);
                    return writer.Encode();
                }

                var certID = new AsnReader(Request, AsnEncodingRules.DER).ReadSequence().  // OCSPRequest
                                                                         ReadSequence().  //   TBSRequest
                                                                         ReadSequence().  //     requestList
                                                                         ReadSequence().  //       Request
                                                                         ReadEncodedValue();

                var serialReader = new AsnReader(certID, AsnEncodingRules.DER).ReadSequence();
                serialReader.ReadSequence();
                serialReader.ReadOctetString();
                serialReader.ReadOctetString();
                var serial       = Convert.ToHexString(serialReader.ReadIntegerBytes().Span).TrimStart('0').ToLowerInvariant();

                var now          = DateTimeOffset.UtcNow;
                var basic        = new AsnWriter(AsnEncodingRules.DER);

                using (basic.PushSequence())                                            // BasicOCSPResponse
                {

                    using (basic.PushSequence())                                        //   ResponseData
                    {

                        using (basic.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
                            basic.WriteOctetString(new Byte[20]);                       //     responderID byKey

                        basic.WriteGeneralizedTime(now);                                //     producedAt

                        using (basic.PushSequence())                                    //     responses
                        using (basic.PushSequence())                                    //       SingleResponse
                        {

                            basic.WriteEncodedValue(certID.Span);

                            if (Revoked.ContainsKey(serial))
                                using (basic.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                                    basic.WriteGeneralizedTime(now.AddDays(-2));
                            else
                                basic.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0));

                            basic.WriteGeneralizedTime(now);                            //         thisUpdate

                            using (basic.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                                basic.WriteGeneralizedTime(now.AddHours(1));            //         nextUpdate

                        }

                    }

                    using (basic.PushSequence())
                        basic.WriteObjectIdentifier("1.2.840.10045.4.3.2");

                    basic.WriteBitString(new Byte[64]);

                }

                using (writer.PushSequence())                                           // OCSPResponse
                {
                    writer.WriteEnumeratedValue(OCSPResponseStatus.Successful);
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(OCSPMessages.BasicResponseOID);
                        writer.WriteOctetString(basic.Encode());
                    }
                }

                return writer.Encode();

            }

            public enum OCSPResponseStatus
            {
                Successful  = 0,
                TryLater    = 3
            }

            /// <summary>
            /// A certs-only PKCS#7: a SignedData of no signers, RFC 5652.
            /// </summary>
            private static Byte[] CertsOnly(params X509Certificate2[] Certificates)
            {

                var writer = new AsnWriter(AsnEncodingRules.DER);

                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    using (writer.PushSequence())
                    {
                        writer.WriteInteger(1);
                        using (writer.PushSetOf()) { }
                        using (writer.PushSequence())
                            writer.WriteObjectIdentifier("1.2.840.113549.1.7.1");
                        using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                            foreach (var certificate in Certificates)
                                writer.WriteEncodedValue(certificate.RawData);
                        using (writer.PushSetOf()) { }
                    }
                }

                return writer.Encode();

            }

            public void Dispose()
            {
                stop.Cancel();
                listener.Stop();
                CA.Dispose();
            }

        }

        #endregion

    }

}
