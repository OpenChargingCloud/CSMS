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
using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The detailed test of one time server, against a real one: Norn's own,
    /// on this machine, with the self-signed certificate it makes itself.
    /// </summary>
    /// <remarks>
    /// Nothing goes out. The CSMS gets a name server of its own, which knows
    /// "localhost" from its cache and asks nobody else: its one server is a
    /// port on this machine that nothing listens on. The time server listens
    /// on the loopback ports found free for it.
    /// </remarks>
    [TestFixture]
    public class TimeServerTestTests
    {

        #region (private static) FreeUDPPort()

        private static IPPort FreeUDPPort()
        {

            using var udp = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse((UInt16) ((IPEndPoint) udp.Client.LocalEndPoint!).Port);

        }

        #endregion


        #region ARefusedCertificateIsDescribedBeforeTheExchangeIsSaidToHaveFailed()

        /// <summary>
        /// The test says what the certificate was and why it was refused,
        /// before it says that the key exchange failed over it.
        /// </summary>
        /// <remarks>
        /// It used to go from the timings straight to "The key exchange
        /// failed", with nothing about the certificate it had failed over -
        /// the one moment somebody most needs to be told what it was.
        /// </remarks>
        [Test]
        public async Task ARefusedCertificateIsDescribedBeforeTheExchangeIsSaidToHaveFailed()
        {

            var ntsKEPort  = IPPort.Parse(TestCSMSs.FreePort());
            var ntpPort    = FreeUDPPort();

            var server     = new NTSServer(NTSKEPort:           ntsKEPort,
                                           NTSPort:             ntpPort,
                                           ExternalURLs:        [ URL.Parse($"udp://localhost:{ntpPort}") ],
                                           MasterKeysFilePath:  null);

            await server.Start();

            var directory  = TestCSMSs.TemporaryDirectory("time-server-test");

            try
            {

                var dnsClient = new DNSClient([ new DNSServerConfig(IPv4Address.Localhost, FreeUDPPort()) ],
                                              QueryTimeout: TimeSpan.FromSeconds(1));

                dnsClient.DNSCache.Add(DNSServiceName.Parse("localhost"),
                                       new A   (DomainName.Parse("localhost"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost),
                                       new AAAA(DomainName.Parse("localhost"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv6Address.Localhost));

                var configuration = new JObject(
                                        new JProperty("nts", new JObject(
                                            new JProperty("servers", new JArray(new JObject(
                                                new JProperty("hostname",   "localhost"),
                                                new JProperty("ntsKEPort",  ntsKEPort.ToUInt16()),
                                                new JProperty("ntpPort",    ntpPort.  ToUInt16())
                                            ))),
                                            new JProperty("timeoutSeconds", 5)
                                        ))
                                    );

                Directory.CreateDirectory(directory);
                File.WriteAllText(Path.Combine(directory, "configuration.json"), configuration.ToString());

                await using var csms = new CSMS(
                                           DNSClient:       dnsClient,
                                           HTTPPort:        IPPort.Parse(TestCSMSs.FreePort()),
                                           AccountsPath:    Path.Combine(directory, "accounts"),
                                           ConfigFile:      new WWCPConfigFile(Path.Combine(directory, "configuration.json")),
                                           LogToConsole:    false,
                                           BridgeDebugLog:  false
                                       );

                var result  = await csms.TestTimeServerAsync("localhost");
                var steps   = result["steps"]!.Select(step => step.Value<String>("text") ?? "").ToArray();

                var certificate  = Array.FindIndex(steps, step => step.StartsWith("Server certificate",  StringComparison.Ordinal));
                var verdict      = Array.FindIndex(steps, step => step.StartsWith("Not validated:",      StringComparison.Ordinal));
                var failed       = Array.FindIndex(steps, step => step.StartsWith("The key exchange failed", StringComparison.Ordinal));

                Assert.Multiple(() => {

                    Assert.That(certificate,  Is.GreaterThanOrEqualTo(0),  String.Join(" | ", steps));
                    Assert.That(steps.ElementAtOrDefault(certificate),  Does.Contain("ntpKE.example.org"));

                    Assert.That(steps.ElementAtOrDefault(verdict),      Does.Contain("its root is not one this machine trusts"),  String.Join(" | ", steps));

                    Assert.That(failed,       Is.GreaterThan(verdict),  "the exchange was said to have failed before its certificate was described");

                });

            }
            finally
            {
                server.Shutdown();
                TestCSMSs.Remove(directory);
            }

        }

        #endregion

    }

}
