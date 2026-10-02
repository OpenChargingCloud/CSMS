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

using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// A CSMS whose stopping fails: it says so, and all the same both its
    /// ports are closed, it is not stopped a second time, and letting go of it
    /// lets go of its log file.
    /// </summary>
    /// <remarks>
    /// What fails is the tests' hook into stopping, before the charging
    /// station server stops. The web interface's port and the log file are the
    /// node's to let go of, since WWCP_Node 68aeac6 even where stopping fails;
    /// the charging station port is this CSMS's.
    ///
    /// Each test makes a CSMS of its own, with its charging station server
    /// switched on and a log file, and lets go of it itself.
    /// </remarks>
    [TestFixture]
    public class StopThatFailsTests
    {

        #region Data

        private const String Why = "What this CSMS holds open would not end.";

        private String  directory  = default!;
        private CSMS?   csms;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public async Task StartTheCSMS()
        {

            directory = TestCSMSs.TemporaryDirectory("stop-fails");

            csms      = await TestPorts.StartedOnFreshPorts(() => {

                            TestCSMSs.Remove(directory);
                            Directory.CreateDirectory(directory);

                            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

                            File.WriteAllText(
                                configuration,
                                new JObject(
                                    new JProperty("nts",  new JObject(new JProperty("enabled", false))),
                                    new JProperty("ocppServer", new JObject(
                                        new JProperty("enabled",           true),
                                        new JProperty("address",           "127.0.0.1"),
                                        new JProperty("port",              TestPorts.Free()),
                                        new JProperty("securityProfiles",  new JArray(1))
                                    ))
                                ).ToString()
                            );

                            return new CSMS(
                                       HTTPPort:        IPPort.Parse(TestPorts.Free()),
                                       AccountsPath:    Path.Combine(directory, "accounts"),
                                       ConfigFile:      new WWCPConfigFile(configuration),
                                       LogToConsole:    false,
                                       LogPath:         Path.Combine(directory, "logs"),
                                       BridgeDebugLog:  false
                                   );

                        });

        }

        [TearDown]
        public async Task LetGoOfTheCSMS()
        {

            if (csms is not null)
            {

                csms.WhileStopping = null;

                try
                {
                    await csms.DisposeAsync();
                }
                catch (InvalidOperationException)
                {
                    // Its stopping fails, where it was not let go of before.
                }

            }

            TestCSMSs.Remove(directory);

        }

        #endregion


        #region (private) FailingToStop()

        /// <summary>
        /// The CSMS, its stopping made to fail, and how often it was asked to
        /// stop.
        /// </summary>
        private CSMS FailingToStop(out Func<Int32> Stoppings)
        {

            var stoppings = 0;

            csms!.WhileStopping = () => {
                stoppings++;
                throw new InvalidOperationException(Why);
            };

            Stoppings = () => stoppings;

            return csms;

        }

        #endregion

        #region (private) LetGoOfHere()

        /// <summary>
        /// The CSMS, for a test that lets go of it itself, rather than the
        /// TearDown a second time.
        /// </summary>
        private CSMS LetGoOfHere()
        {

            var here = csms!;

            csms = null;

            return here;

        }

        #endregion

        #region (private static) Refused(Port)

        /// <summary>
        /// Whether nothing listens on the given port of the loopback address.
        /// </summary>
        private static async Task<Boolean> Refused(UInt16 Port)
        {

            using var client = new TcpClient();

            try
            {
                await client.ConnectAsync(System.Net.IPAddress.Loopback, Port);
                return false;
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return true;
            }

        }

        #endregion

        #region (private static) Read(Directory)

        /// <summary>
        /// What the log file of the CSMS says, read beside whoever may still be
        /// writing it.
        /// </summary>
        private static String Read(String Directory)
        {

            var file = System.IO.Directory.GetFiles(Path.Combine(Directory, "logs"), "csms-*.log").Single();

            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();

        }

        #endregion


        #region AStopThatFailsSaysSoAndStillClosesBothPorts()

        /// <summary>
        /// The failure reaches whoever stopped the CSMS - and both its ports
        /// are closed all the same: a browser and a charging station that come
        /// to it are refused, not answered by a CSMS that thinks it has
        /// stopped.
        /// </summary>
        [Test]
        public async Task AStopThatFailsSaysSoAndStillClosesBothPorts()
        {

            var failing      = FailingToStop(out _);
            var webPort      = failing.HTTPPort.ToUInt16();
            var stationPort  = failing.OCPPServerSettings.TCPPort!.Value.ToUInt16();

            Assert.That(await Refused(stationPort), Is.False, "The charging station port was not open before, so the test below proves nothing.");

            Assert.That(async () => await failing.Stop(),
                        Throws.InstanceOf<InvalidOperationException>().With.Message.EqualTo(Why));

            var webRefused      = await Refused(webPort);
            var stationRefused  = await Refused(stationPort);

            Assert.Multiple(() => {
                Assert.That(webRefused,      Is.True, "The CSMS still listens on the port of its web interface.");
                Assert.That(stationRefused,  Is.True, "The CSMS still listens on its charging station port.");
            });

        }

        #endregion

        #region ACSMSWhoseStopFailedIsNotStoppedAgain()

        /// <summary>
        /// Stopped is stopped, even where stopping failed: a second stop, and
        /// the one letting go of the CSMS does, do nothing, and so cannot fail
        /// the same way again.
        /// </summary>
        [Test]
        public async Task ACSMSWhoseStopFailedIsNotStoppedAgain()
        {

            FailingToStop(out var stoppings);

            var failing = LetGoOfHere();

            Assert.That(async () => await failing.Stop(), Throws.InstanceOf<InvalidOperationException>());

            Assert.Multiple(() => {
                Assert.That(async () => await failing.Stop(),          Throws.Nothing,  "A second stop started over.");
                Assert.That(async () => await failing.DisposeAsync(),  Throws.Nothing,  "Letting go of a stopped CSMS stopped it again.");
                Assert.That(stoppings(),                               Is.EqualTo(1),   "Stopping was begun again.");
            });

        }

        #endregion

        #region LettingGoOfACSMSWhoseStopFailsLetsGoOfItsLogFile()

        /// <summary>
        /// Letting go of a CSMS whose stopping fails says that it failed - and
        /// lets go of it all the same: nothing logged afterwards reaches its
        /// log file, which is closed.
        /// </summary>
        [Test]
        public async Task LettingGoOfACSMSWhoseStopFailsLetsGoOfItsLogFile()
        {

            FailingToStop(out _);

            var failing = LetGoOfHere();

            failing.Log.Notice("Written while the CSMS runs.", "test");

            Assert.That(async () => await failing.DisposeAsync(), Throws.InstanceOf<InvalidOperationException>());

            failing.Log.Notice("Written after the CSMS was let go of.", "test");

            var written = Read(directory);

            Assert.Multiple(() => {
                Assert.That(written, Does.Contain    ("Written while the CSMS runs."));
                Assert.That(written, Does.Not.Contain("Written after the CSMS was let go of."),
                            "The log file of a CSMS that was let go of was still written.");
            });

        }

        #endregion

    }

}
