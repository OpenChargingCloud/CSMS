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
using System.Net.WebSockets;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.CommandLine;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// stationSyncNTS: a CSMS asks a charging station connected to it to ask
    /// its time servers now, or to test one of them step by step, and writes
    /// down what the station told it in the lines of the node's own syncNTS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The messages themselves - SyncNetworkTime, TestTimeServer and
    /// NotifyNetworkTimeResult - are WWCP_OCPP's, and tested there. What is
    /// tested here is the command: what it takes from the words typed, that it
    /// waits for the result of its own request and of no other, and what it
    /// writes.
    /// </para>
    /// <para>
    /// The station is a plain WebSocket that answers every CALL as the test
    /// says, rather than a charging station of the OCPP library: one that
    /// asked its time servers for real would make the test depend on the
    /// network, and one that answers as told can also answer wrongly.
    /// </para>
    /// </remarks>
    public class StationSyncNTSCommandTests : ACSMSTests
    {

        #region Data

        private const String ThePassword = "a-password-long-enough-for-ocpp";

        private ClientWebSocket?          station;
        private CancellationTokenSource   stop    = new();
        private Task?                     loop;

        /// <summary>
        /// Every CALL the station got, in its order.
        /// </summary>
        private readonly ConcurrentQueue<JArray>  calls  = new();

        /// <summary>
        /// What the station sends for a CALL: its action and payload, and how
        /// many came before it. "{id}" in a frame is the id of that CALL.
        /// Nothing at all is answered with a CALLERROR NotImplemented.
        /// </summary>
        private Func<String, JObject, Int32, JArray[]>  onCall  = (action, payload, n) => [];

        #endregion

        #region (override) Configuration

        /// <summary>
        /// A CSMS whose charging station server is switched on, on the
        /// loopback address, over security profile 1.
        /// </summary>
        protected override JObject Configuration
            => new (
                   new JProperty("nts",  new JObject(new JProperty("groups", new JObject(new JProperty("legal", new JObject(new JProperty("enabled", false))))))),
                   new JProperty("ocppServer", new JObject(
                       new JProperty("enabled",           true),
                       new JProperty("address",           "127.0.0.1"),
                       new JProperty("port",              TestPorts.Free()),
                       new JProperty("securityProfiles",  new JArray(1)),
                       new JProperty("subprotocols",      new JArray("ocpp2.1"))
                   ))
               );

        #endregion

        #region SetUp / TearDown

        /// <summary>
        /// The charging station cs001, connected and counted as connected.
        /// </summary>
        /// <remarks>
        /// After the base class's SetUp, which NUnit runs first. The fields are
        /// made again for every test: NUnit keeps one instance of a fixture for
        /// all of its tests.
        /// </remarks>
        [SetUp]
        public async Task ConnectTheStation()
        {

            stop    = new CancellationTokenSource();
            onCall  = (action, payload, n) => [];
            calls.Clear();

            Assert.That(CSMS.StationLogins.TrySetPassword("cs001", ThePassword, null, null, out _, out var error), Is.True, error);

            station = new ClientWebSocket();
            station.Options.AddSubProtocol("ocpp2.1");
            station.Options.SetRequestHeader("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"cs001:{ThePassword}")));

            await station.ConnectAsync(new Uri($"ws://127.0.0.1:{CSMS.OCPPServerSettings.TCPPort}"), CancellationToken.None);

            loop = Task.Run(Answer);

            for (var i = 0; i < 50 && !CSMS.IsConnected("cs001"); i++)
                await Task.Delay(100);

            Assert.That(CSMS.IsConnected("cs001"), Is.True, "the station never counted as connected");

        }

        [TearDown]
        public async Task DisconnectTheStation()
        {

            stop.Cancel();

            try { station?.Abort(); }               catch { }
            try { if (loop is not null) await loop; } catch { }

            station?.Dispose();
            stop.Dispose();

        }

        #endregion

        #region (private) Answer()

        /// <summary>
        /// What the station does while it is connected: reads a frame, and
        /// answers a CALL with what <see cref="onCall"/> says.
        /// </summary>
        private async Task Answer()
        {

            var buffer  = new Byte[1 << 16];
            var n       = 0;

            while (!stop.IsCancellationRequested && station!.State == WebSocketState.Open)
            {

                var text = new StringBuilder();
                WebSocketReceiveResult result;

                do
                {
                    result = await station.ReceiveAsync(buffer, stop.Token);
                    text.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                }
                while (!result.EndOfMessage);

                if (result.MessageType == WebSocketMessageType.Close)
                    return;

                var frame = JArray.Parse(text.ToString());

                // A response to one of the station's own CALLs.
                if (frame[0]!.Value<Int32>() != 2)
                    continue;

                calls.Enqueue(frame);

                var id       = frame[1]!.Value<String>()!;
                var answers  = onCall(frame[2]!.Value<String>()!, (JObject) frame[3]!, n++);

                if (answers.Length == 0)
                    answers = [ new JArray(4, "{id}", "NotImplemented", "", new JObject()) ];

                foreach (var answer in answers)
                    await station.SendAsync(Encoding.UTF8.GetBytes(answer.ToString(Newtonsoft.Json.Formatting.None).Replace("\"{id}\"", $"\"{id}\"")),
                                            WebSocketMessageType.Text,
                                            true,
                                            stop.Token);

            }

        }

        #endregion

        #region (private) Run(params Words)

        /// <summary>
        /// The command, typed at the console of this CSMS.
        /// </summary>
        private async Task<String[]> Run(params String[] Words)
        {

            using var cli    = new CSMSCLI(CSMS);
            var       lines  = await new StationSyncNTSCommand(cli).Execute(Words, CancellationToken.None);

            TestContext.Out.WriteLine(String.Join(Environment.NewLine, lines));

            return lines;

        }

        #endregion

        #region (private static) Notify(Payload) / Accepted

        /// <summary>
        /// What a station sends when it has the result: a CALL of its own.
        /// </summary>
        private static JArray Notify(JObject Payload)
            => new (2, Guid.NewGuid().ToString(), "NotifyNetworkTimeResult", Payload);

        /// <summary>
        /// The station takes the request on.
        /// </summary>
        private static JArray Accepted
            => new (3, "{id}", new JObject(new JProperty("status", "Accepted")));

        #endregion


        #region ARoundOfTheLegalGroupIsAskedForAndToldInTheLinesOfSyncNTS()

        /// <summary>
        /// Without a group, the station asks the group it would ask anyway, and
        /// what it found is written as syncNTS writes a round of its own.
        /// </summary>
        [Test]
        public async Task ARoundOfTheLegalGroupIsAskedForAndToldInTheLinesOfSyncNTS()
        {

            onCall = (action, payload, n) => action == "SyncNetworkTime"
                ? [ Accepted,
                    Notify(JObject.Parse($$"""
                        { "requestId": {{payload["requestId"]}}, "generatedAt": "2026-11-10T16:00:00Z",
                          "round": { "group": "legal", "ok": true, "duration": 0.312, "answered": 1, "required": 1,
                                     "offset": 0.0012, "spread": 0, "legalTime": false, "legalTimeReason": "Only one of two required servers is configured.",
                                     "clients": [ { "client": "ptb1", "host": "ptbtime1.ptb.de", "ok": true, "offset": 0.0012, "roundTrip": 0.0187, "keyExchange": "New" },
                                                  { "client": "ptb2", "host": "ptbtime2.ptb.de", "ok": false, "error": "No answer within 3 s." } ] } }
                        """)) ]
                : [];

            var lines = await Run("stationSyncNTS", "cs001");

            Assert.That(calls.Single(call => call[2]!.Value<String>() == "SyncNetworkTime")[3]!["group"], Is.Null, "no group was typed");

            Assert.That(lines, Is.EqualTo(new[] {
                "Asked of the charging station 'cs001', NTS group 'legal':",
                "succeeded after 312 ms: 1 of 2 server(s) answered (1 required), offset +1.2 ms, spread 0.0 ms",
                "  ptbtime1.ptb.de (ptb1)  +1.2 ms, round trip 18.7 ms, key exchange new",
                "  ptbtime2.ptb.de (ptb2)  No answer within 3 s.",
                "  legal time: no - Only one of two required servers is configured."
            }));

        }

        #endregion

        #region AGroupNamedIsSentAndItsRefusalSaid()

        /// <summary>
        /// A group typed is the group asked for, and a station that has no
        /// such group says so - in its own words.
        /// </summary>
        [Test]
        public async Task AGroupNamedIsSentAndItsRefusalSaid()
        {

            onCall = (action, payload, n) => action == "SyncNetworkTime"
                ? [ new JArray(3, "{id}", JObject.Parse("""{ "status": "Rejected", "statusInfo": { "reasonCode": "UnknownGroup", "additionalInfo": "There is no NTS group 'grid' here; there are legal, local." } }""")) ]
                : [];

            var lines = await Run("stationSyncNTS", "cs001", "grid");

            Assert.That(calls.Single()[3]!["group"]?.Value<String>(), Is.EqualTo("grid"));
            Assert.That(lines, Is.EqualTo(new[] { "'cs001' asked nobody: Rejected, UnknownGroup - There is no NTS group 'grid' here; there are legal, local." }));

        }

        #endregion

        #region ATestOfAClientIsToldStepByStepWithWhereItFailed()

        /// <summary>
        /// "@client" asks for the test of one time server, and it is written
        /// step by step, with where it failed - even where the station tells
        /// it before it answers the request, and after the result of another
        /// request.
        /// </summary>
        [Test]
        public async Task ATestOfAClientIsToldStepByStepWithWhereItFailed()
        {

            onCall = (action, payload, n) => action == "TestTimeServer"
                ? [ Notify(JObject.Parse("""{ "requestId": 1, "generatedAt": "2026-11-10T16:00:00Z", "test": { "host": "x", "ok": true, "duration": 0, "steps": [] } }""")),
                    Notify(JObject.Parse($$"""
                        { "requestId": {{payload["requestId"]}}, "generatedAt": "2026-11-10T16:00:00Z",
                          "test": { "client": "ptb2", "host": "ptbtime2.ptb.de", "ok": false, "failedAt": "TimeRequest", "duration": 3.096,
                                    "steps": [ { "elapsed": 0,     "stage": "Configuration", "level": "Info",   "text": "Asking ptbtime2.ptb.de." },
                                               { "elapsed": 0.094, "stage": "KeyExchange",   "level": "Notice", "text": "The key exchange succeeded." },
                                               { "elapsed": 3.096, "stage": "TimeRequest",   "level": "Error",  "text": "No answer within 3 s." } ] } }
                        """)),
                    Accepted ]
                : [];

            var lines = await Run("stationSyncNTS", "cs001", "@ptb2");

            Assert.That(calls.Single(call => call[2]!.Value<String>() == "TestTimeServer")[3]!["client"]?.Value<String>(), Is.EqualTo("ptb2"));

            Assert.That(lines, Is.EqualTo(new[] {
                "Asked of the charging station 'cs001':",
                "ptbtime2.ptb.de (ptb2) did not answer, 3096 ms altogether:",
                "     +0 ms  Asking ptbtime2.ptb.de.",
                "    +94 ms  The key exchange succeeded.",
                "  +3096 ms  error: No answer within 3 s.",
                "  failed at: TimeRequest"
            }));

        }

        #endregion

        #region AStationThatIsNotConnectedIsNotAsked()

        [Test]
        public async Task AStationThatIsNotConnectedIsNotAsked()
        {

            var lines = await Run("stationSyncNTS", "cs404");

            Assert.That(lines, Is.EqualTo(new[] { "The charging station 'cs404' is not connected." }));
            Assert.That(calls, Is.Empty);

        }

        #endregion

        #region UsageWhereTheWordsAreNotEnoughOrTooMany()

        [Test]
        public async Task UsageWhereTheWordsAreNotEnoughOrTooMany()
        {

            Assert.That((await Run("stationSyncNTS")).Single(),                             Does.StartWith("Usage: stationSyncNTS <station> [<group> | @<client>]"));
            Assert.That((await Run("stationSyncNTS", "cs001", "@")).Single(),               Does.StartWith("Usage: "));
            Assert.That((await Run("stationSyncNTS", "cs001", "legal", "@ptb1")).Single(),  Does.StartWith("Usage: "));
            Assert.That(calls, Is.Empty);

        }

        #endregion

        #region ACallErrorIsSaid()

        [Test]
        public async Task ACallErrorIsSaid()
        {

            onCall = (action, payload, n) => [ new JArray(4, "{id}", "NotImplemented", "SyncNetworkTime is unknown here.", new JObject()) ];

            Assert.That((await Run("stationSyncNTS", "cs001")).Single(), Does.StartWith("'cs001' did not answer: "));

        }

        #endregion

        #region OverSSHTheCSMSHasItsOwnCommands()

        /// <summary>
        /// Whoever signs in over SSH gets the command line of the CSMS, with
        /// its commands, without the program that runs it having to say so:
        /// the test environment runs a CSMS without the program CSMSCLI.
        /// </summary>
        [Test]
        public async Task OverSSHTheCSMSHasItsOwnCommands()
        {

            Assert.That(CSMS.CommandLines, Is.Not.Null, "a session over SSH would get the node's command line only");

            await using var terminal  = new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask);
            using       var cli       = CSMS.CommandLines!(terminal, CLICaller.Console);

            Assert.That(cli, Is.InstanceOf<CSMSCLI>());

            foreach (var command in new[] { "stationSyncNTS", "stationQueryDNS", "stationKeys" })
                Assert.That(String.Join(" | ", await cli.Execute(command)), Does.Not.StartWith("Unknown command"), command);

            Assert.That((await cli.Execute("stationSyncNTS")).Single(), Does.StartWith("Usage: stationSyncNTS"));

        }

        #endregion

    }

}
