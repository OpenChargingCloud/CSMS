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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;

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
    /// </remarks>
    public class StationSyncNTSCommandTests : AConnectedStationTests
    {

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

        #region ARoundOfTheLegalGroupIsAskedForAndToldInTheLinesOfSyncNTS()

        /// <summary>
        /// Without a group, the station asks the group it would ask anyway, and
        /// what it found is written as syncNTS writes a round of its own.
        /// </summary>
        [Test]
        public async Task ARoundOfTheLegalGroupIsAskedForAndToldInTheLinesOfSyncNTS()
        {

            OnCall = (action, payload, n) => action == "SyncNetworkTime"
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

            Assert.That(Calls.Single(call => call[2]!.Value<String>() == "SyncNetworkTime")[3]!["group"], Is.Null, "no group was typed");

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

            OnCall = (action, payload, n) => action == "SyncNetworkTime"
                ? [ new JArray(3, "{id}", JObject.Parse("""{ "status": "Rejected", "statusInfo": { "reasonCode": "UnknownGroup", "additionalInfo": "There is no NTS group 'grid' here; there are legal, local." } }""")) ]
                : [];

            var lines = await Run("stationSyncNTS", "cs001", "grid");

            Assert.That(Calls.Single()[3]!["group"]?.Value<String>(), Is.EqualTo("grid"));
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

            OnCall = (action, payload, n) => action == "TestTimeServer"
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

            Assert.That(Calls.Single(call => call[2]!.Value<String>() == "TestTimeServer")[3]!["client"]?.Value<String>(), Is.EqualTo("ptb2"));

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
            Assert.That(Calls, Is.Empty);

        }

        #endregion

        #region UsageWhereTheWordsAreNotEnoughOrTooMany()

        [Test]
        public async Task UsageWhereTheWordsAreNotEnoughOrTooMany()
        {

            Assert.That((await Run("stationSyncNTS")).Single(),                             Does.StartWith("Usage: stationSyncNTS <station> [<group> | @<client>]"));
            Assert.That((await Run("stationSyncNTS", "cs001", "@")).Single(),               Does.StartWith("Usage: "));
            Assert.That((await Run("stationSyncNTS", "cs001", "legal", "@ptb1")).Single(),  Does.StartWith("Usage: "));
            Assert.That(Calls, Is.Empty);

        }

        #endregion

        #region ACallErrorIsSaid()

        [Test]
        public async Task ACallErrorIsSaid()
        {

            OnCall = (action, payload, n) => [ new JArray(4, "{id}", "NotImplemented", "SyncNetworkTime is unknown here.", new JObject()) ];

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
