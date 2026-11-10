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
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The root certificates of the charging stations: kept by the CSMS,
    /// installed on a station by hand and on every station that starts without
    /// one that every station is to have, and deleted from a station - against
    /// a station that keeps what it is installed, as a station does.
    /// </summary>
    public class StationRootsTests : ACSMSTests
    {

        #region Data

        private const String ThePassword = "a-password-long-enough-for-ocpp";

        private readonly List<TestCA> cas = [];

        #endregion

        #region (override) Configuration

        protected override JObject Configuration

            => new (
                   new JProperty("nts",  new JObject(new JProperty("groups", new JObject(new JProperty("legal", new JObject(new JProperty("enabled", false))))))),
                   new JProperty("ocppServer", new JObject(
                       new JProperty("enabled",           true),
                       new JProperty("address",           "127.0.0.1"),
                       new JProperty("port",              TestPorts.Free()),
                       new JProperty("securityProfiles",  new JArray(1)),
                       new JProperty("subprotocols",      new JArray("ocpp2.1", "ocpp2.0.1"))
                   ))
               );

        [TearDown]
        public void DisposeTheCAs()
        {
            foreach (var ca in cas)
                ca.Dispose();
            cas.Clear();
        }

        private String ARoot(String Name)
        {
            var ca = TestCA.Create(Name);
            cas.Add(ca);
            return TestCA.ToPEM(ca.Certificate);
        }

        #endregion


        #region ARootIsKept()

        /// <summary>
        /// A root added, kept in its file, and refused where it is no root.
        /// </summary>
        [Test]
        public async Task ARootIsKept()
        {

            using var browser = await SignedIn();

            var root          = ARoot("Station Root A");
            var sub           = TestCA.Create("Sub", WithIntermediate: true);
            cas.Add(sub);

            using var added   = await browser.PostAsync("api/v1/configuration/station-roots",
                                                        JSONBody(new JProperty("pem", root), new JProperty("certificateType", "CSMSRootCertificate"), new JProperty("everywhere", true)));

            using var twice   = await browser.PostAsync("api/v1/configuration/station-roots",
                                                        JSONBody(new JProperty("pem", root), new JProperty("certificateType", "CSMSRootCertificate")));

            using var noRoot  = await browser.PostAsync("api/v1/configuration/station-roots",
                                                        JSONBody(new JProperty("pem", TestCA.ToPEM(sub.Intermediate!)), new JProperty("certificateType", "CSMSRootCertificate")));

            using var badType = await browser.PostAsync("api/v1/configuration/station-roots",
                                                        JSONBody(new JProperty("pem", root), new JProperty("certificateType", "ChargingStationCertificate")));

            var shown         = JObject.Parse(await added.Content.ReadAsStringAsync());
            var again         = new StationRoots(CSMS.StationRoots.Path);
            again.Load();

            Assert.Multiple(() => {
                Assert.That(added.StatusCode,                                   Is.EqualTo(HttpStatusCode.Created), shown.ToString());
                Assert.That(shown["roots"]![0]!["subject"]!.Value<String>(),    Does.Contain("Station Root A"));
                Assert.That(shown["roots"]![0]!["everywhere"]!.Value<Boolean>(), Is.True);
                Assert.That(twice.StatusCode,                                   Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(noRoot.StatusCode,                                  Is.EqualTo(HttpStatusCode.BadRequest), "an intermediate is no root");
                Assert.That(badType.StatusCode,                                 Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(again.All.Count,                                    Is.EqualTo(1), "kept in its file");
            });

            var id            = shown["roots"]![0]!["id"]!.Value<String>();

            using var off     = await browser.PutAsync($"api/v1/configuration/station-roots/CSMSRootCertificate/{id}",
                                                       JSONBody(new JProperty("everywhere", false)));
            using var gone    = await browser.DeleteAsync($"api/v1/configuration/station-roots/CSMSRootCertificate/{id}");
            using var unknown = await browser.DeleteAsync($"api/v1/configuration/station-roots/CSMSRootCertificate/{id}");

            Assert.Multiple(() => {
                Assert.That(off.StatusCode,          Is.EqualTo(HttpStatusCode.OK));
                Assert.That(gone.StatusCode,         Is.EqualTo(HttpStatusCode.OK));
                Assert.That(unknown.StatusCode,      Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(CSMS.StationRoots.All,   Is.Empty);
            });

        }

        #endregion

        #region ARootIsInstalledLookedAtAndDeleted()

        /// <summary>
        /// Installed on a station by hand, seen among what it has as the root
        /// it is, and deleted from it again.
        /// </summary>
        [Test]
        public async Task ARootIsInstalledLookedAtAndDeleted()
        {

            using var station = await FakeStation.Connect(CSMS, "cs001", ThePassword);
            using var browser = await SignedIn();

            var pem           = ARoot("V2G Root B");
            Assert.That(CSMS.StationRoots.TryAdd(pem, "V2GRootCertificate", false, DateTimeOffset.UtcNow, out var root, out var error), Is.True, error);

            station.Installed.Add(("ManufacturerRootCertificate", "SHA256", "aa", "bb", "1234"));

            using var installed = await browser.PostAsync($"api/v1/configuration/station-roots/V2GRootCertificate/{root!.Id}/install",
                                                          JSONBody(new JProperty("station", "cs001")));
            var result          = JObject.Parse(await installed.Content.ReadAsStringAsync());

            var looked          = JObject.Parse(await browser.GetStringAsync("api/v1/configuration/station-roots/stations/cs001"));
            var ours            = looked["installed"]!.Single(one => one["certificateType"]!.Value<String>() == "V2GRootCertificate");

            Assert.Multiple(() => {
                Assert.That(installed.StatusCode,                                   Is.EqualTo(HttpStatusCode.OK), result.ToString());
                Assert.That(result["results"]![0]!["answer"]!.Value<String>(),      Is.EqualTo("Accepted"));
                Assert.That(station.Installed.Count,                                Is.EqualTo(2));
                Assert.That(ours["root"]!.Value<String>(),                          Is.EqualTo(root.Id), "known as the root it is");
                Assert.That(looked["installed"]!.Count(one => one["root"]!.Type == JTokenType.Null), Is.EqualTo(1), "the other is nobody's here");
            });

            using var deleted   = await browser.PostAsync("api/v1/configuration/station-roots/stations/cs001/delete",
                                                          JSONBody(new JProperty("certificateType",  "V2GRootCertificate"),
                                                                   new JProperty("hashAlgorithm",    ours["hashAlgorithm"]!.Value<String>()),
                                                                   new JProperty("issuerNameHash",   ours["issuerNameHash"]!.Value<String>()),
                                                                   new JProperty("issuerKeyHash",    ours["issuerKeyHash"]!.Value<String>()),
                                                                   new JProperty("serialNumber",     ours["serialNumber"]!.Value<String>())));

            using var away      = await browser.GetAsync("api/v1/configuration/station-roots/stations/cs999");
            var shown           = JObject.Parse(await browser.GetStringAsync("api/v1/configuration/station-roots"));

            Assert.Multiple(() => {
                Assert.That(deleted.StatusCode,                                     Is.EqualTo(HttpStatusCode.OK));
                Assert.That(station.Installed.Count,                                Is.EqualTo(1));
                Assert.That(away.StatusCode,                                        Is.EqualTo(HttpStatusCode.Conflict), "not connected");
                Assert.That(shown["connected"]!.Values<String>(),                   Is.EqualTo(new[] { "cs001" }));
                Assert.That(shown["changes"]!.Select(change => change["action"]!.Value<String>()), Is.EqualTo(new[] { "delete", "install" }));
            });

        }

        #endregion

        #region ARootForEveryStationIsInstalledWhereItIsMissing()

        /// <summary>
        /// A root every station is to have: installed on a station that starts
        /// without it - once; not on one that has it.
        /// </summary>
        [Test]
        public async Task ARootForEveryStationIsInstalledWhereItIsMissing()
        {

            using var station = await FakeStation.Connect(CSMS, "cs001", ThePassword);

            Assert.That(CSMS.StationRoots.TryAdd(ARoot("CSMS Root C"), "CSMSRootCertificate", true,  DateTimeOffset.UtcNow, out _, out var error), Is.True, error);
            Assert.That(CSMS.StationRoots.TryAdd(ARoot("MO Root D"),   "MORootCertificate",   false, DateTimeOffset.UtcNow, out _, out error),     Is.True, error);

            await station.Boot();

            await WaitFor(() => station.Installed.Count == 1, "the root for every station was not installed");

            Assert.That(station.Installed.Single().Type, Is.EqualTo("CSMSRootCertificate"), "and only that one");

            await station.Boot();
            await Task.Delay(1500);

            Assert.Multiple(() => {
                Assert.That(station.Installed.Count,                             Is.EqualTo(1), "not installed twice");
                Assert.That(CSMS.StationRootChanges.Single().Automatic,          Is.True);
            });

        }

        #endregion

        #region ARevokedCertificateIsKnownBySerialNumber()

        /// <summary>
        /// A station's certificate is known by its serial number as well, in
        /// either case, with leading zeros or without.
        /// </summary>
        [Test]
        public async Task ARevokedCertificateIsKnownBySerialNumber()
        {

            var now = DateTimeOffset.UtcNow;

            CSMS.StationCertificates.Note("cs001", "ChargingStationCertificate", "aa", now.AddDays(300), "signed", now, now.AddDays(-65), "00AB12");

            var known = CSMS.StationCertificates.Get("cs001", "ChargingStationCertificate")!;

            Assert.Multiple(() => {
                Assert.That(known.HasSerialNumber("ab12"),  Is.True);
                Assert.That(known.HasSerialNumber("0AB12"), Is.True);
                Assert.That(known.HasSerialNumber("ab13"),  Is.False);
            });

        }

        #endregion


        #region (private) WaitFor(Condition, Why)

        private static async Task WaitFor(Func<Boolean> Condition, String Why)
        {
            for (var tries = 0; tries < 100 && !Condition(); tries++)
                await Task.Delay(100);
            Assert.That(Condition(), Is.True, Why);
        }

        #endregion

        #region (private class) FakeStation

        /// <summary>
        /// A charging station that keeps the certificates it is installed, says
        /// what it has, and deletes what it is told to - and nothing else.
        /// </summary>
        private sealed class FakeStation : IDisposable
        {

            private readonly ClientWebSocket          client;
            private readonly CancellationTokenSource  stop = new ();
            private          Int32                    boots;

            /// <summary>
            /// What it has: kind, hash algorithm, hashes and serial number.
            /// </summary>
            public List<(String Type, String Algorithm, String NameHash, String KeyHash, String Serial)> Installed { get; } = [];

            private (String Type, String Algorithm, String NameHash, String KeyHash, String Serial)[] Copy()
            {
                lock (Installed) return [.. Installed];
            }

            private FakeStation(ClientWebSocket Client)
            {
                client = Client;
                _      = Task.Run(Serve);
            }

            public static async Task<FakeStation> Connect(CSMS CSMS, String Id, String Password)
            {

                Assert.That(CSMS.StationLogins.TrySetPassword(Id, Password, null, null, out _, out var error), Is.True, error);

                var client = new ClientWebSocket();
                client.Options.AddSubProtocol("ocpp2.1");
                client.Options.SetRequestHeader("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Id}:{Password}")));

                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(new Uri($"ws://127.0.0.1:{CSMS.OCPPServerSettings.TCPPort}"), timeout.Token);

                return new FakeStation(client);

            }

            public Task Boot()

                => Send(new JArray(2, $"boot-{++boots}", "BootNotification",
                                   new JObject(new JProperty("chargingStation", new JObject(new JProperty("model", "Fake"), new JProperty("vendorName", "OpenChargingCloud"))),
                                               new JProperty("reason", "PowerUp"))));

            private async Task Send(JArray Message)
                => await client.SendAsync(Encoding.UTF8.GetBytes(Message.ToString(Newtonsoft.Json.Formatting.None)), WebSocketMessageType.Text, true, stop.Token);

            private async Task Serve()
            {

                var buffer = new Byte[64 * 1024];

                try
                {
                    while (!stop.IsCancellationRequested)
                    {

                        var message = new MemoryStream();
                        WebSocketReceiveResult received;

                        do
                        {
                            received = await client.ReceiveAsync(buffer, stop.Token);
                            if (received.MessageType == WebSocketMessageType.Close) return;
                            message.Write(buffer, 0, received.Count);
                        }
                        while (!received.EndOfMessage);

                        var call = JArray.Parse(Encoding.UTF8.GetString(message.ToArray()));

                        if (call[0]!.Value<Int32>() != 2)
                            continue;

                        var id      = call[1]!.Value<String>()!;
                        var payload = (JObject) call[3]!;

                        JObject answer = call[2]!.Value<String>() switch {
                            "GetInstalledCertificateIds"  => Copy().Length == 0
                                                                 ? new JObject(new JProperty("status", "NotFound"))
                                                                 : new JObject(new JProperty("status", "Accepted"),
                                                                               new JProperty("certificateHashDataChain", new JArray(Copy().Select(one =>
                                                                                   new JObject(new JProperty("certificateType", one.Type),
                                                                                               new JProperty("certificateHashData", new JObject(
                                                                                                   new JProperty("hashAlgorithm",       one.Algorithm),
                                                                                                   new JProperty("issuerNameHash",      one.NameHash),
                                                                                                   new JProperty("issuerKeyHash",       one.KeyHash),
                                                                                                   new JProperty("serialNumber",        one.Serial)))))))),
                            "InstallCertificate"          => Install(payload),
                            "DeleteCertificate"           => Delete(payload),
                            _                             => new JObject()
                        };

                        await Send(new JArray(3, id, answer));

                    }
                }
                catch (Exception) { }

            }

            private JObject Install(JObject Payload)
            {

                using var certificate = X509Certificate2.CreateFromPem(Payload["certificate"]!.Value<String>()!);

                lock (Installed) Installed.Add((Payload["certificateType"]!.Value<String>()!,
                               "SHA256",
                               Convert.ToHexString(SHA256.HashData(certificate.IssuerName.RawData)).ToLowerInvariant(),
                               Convert.ToHexString(SHA256.HashData(certificate.PublicKey.EncodedKeyValue.RawData)).ToLowerInvariant(),
                               certificate.SerialNumber.TrimStart('0').ToLowerInvariant()));

                return new JObject(new JProperty("status", "Accepted"));

            }

            private JObject Delete(JObject Payload)
            {

                var hash  = Payload["certificateHashData"]!;
                var found = Copy().FirstOrDefault(one => one.NameHash == hash["issuerNameHash"]!.Value<String>() &&
                                                                      one.Serial   == hash["serialNumber"]!.  Value<String>());

                if (found.Type is null)
                    return new JObject(new JProperty("status", "NotFound"));

                lock (Installed) Installed.Remove(found);
                return new JObject(new JProperty("status", "Accepted"));

            }

            public void Dispose()
            {
                stop.Cancel();
                client.Dispose();
            }

        }

        #endregion

    }

}
