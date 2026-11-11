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

using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// A CSMS with one charging station connected to it, cs001, for the
    /// commands that are sent to one.
    /// </summary>
    /// <remarks>
    /// The station is a plain WebSocket that answers every CALL as the test
    /// says, rather than a charging station of the OCPP library: one that did
    /// what it was told for real would make the test about the station, and
    /// one that answers as told can also answer wrongly.
    /// </remarks>
    public abstract class AConnectedStationTests : ACSMSTests
    {

        #region Data

        private const String ThePassword = "a-password-long-enough-for-ocpp";

        private ClientWebSocket?          station;
        private CancellationTokenSource   stop    = new();
        private Task?                     loop;

        /// <summary>
        /// Every CALL the station got, in its order.
        /// </summary>
        protected readonly ConcurrentQueue<JArray>  Calls  = new();

        /// <summary>
        /// What the station sends for a CALL: its action and payload, and how
        /// many came before it. "{id}" in a frame is the id of that CALL.
        /// Nothing at all is answered with a CALLERROR NotImplemented.
        /// </summary>
        protected Func<String, JObject, Int32, JArray[]>  OnCall  = (action, payload, n) => [];

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
            OnCall  = (action, payload, n) => [];
            Calls.Clear();

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
        /// answers a CALL with what <see cref="OnCall"/> says.
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

                Calls.Enqueue(frame);

                var id       = frame[1]!.Value<String>()!;
                var answers  = OnCall(frame[2]!.Value<String>()!, (JObject) frame[3]!, n++);

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

        #region (protected static) Notify(Payload) / Accepted

        /// <summary>
        /// What a station sends when it has the result of something it was
        /// asked: a CALL of its own.
        /// </summary>
        protected static JArray Notify(JObject Payload)
            => new (2, Guid.NewGuid().ToString(), "NotifyNetworkTimeResult", Payload);

        /// <summary>
        /// The station takes the request on.
        /// </summary>
        protected static JArray Accepted
            => new (3, "{id}", new JObject(new JProperty("status", "Accepted")));

        #endregion

    }

}
