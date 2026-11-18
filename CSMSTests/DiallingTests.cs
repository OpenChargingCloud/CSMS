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
using System.Text;

using Newtonsoft.Json.Linq;
using NUnit.Framework;

using cloud.charging.open.protocols.WWCP;
using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The charging stations and local controllers this CSMS dials: the ones
    /// that cannot dial it, and serve OCPP themselves for it.
    /// </summary>
    /// <remarks>
    /// What is at the other end here is a WebSocket server written by hand,
    /// which sees exactly what the CSMS sent it - the path it dialled, what
    /// it signed in with, what it said of its networking mode - and says in
    /// OCPP what a charging station says. OCPP is as it always is: the
    /// station tells the CSMS that it started, and the CSMS asks.
    /// </remarks>
    [TestFixture]
    public class DiallingTests : ACSMSTests
    {

        #region Data

        private const String  ThePassword  = "a-password-the-csms-signs-in-with";

        /// <summary>
        /// The name the station lets this CSMS in under.
        /// </summary>
        private String                             comesUnder = "csms-01";

        private HttpListener?                      listener;
        private Int32                              port;
        private CancellationTokenSource            stop       = new ();
        private Task?                              accepting;

        /// <summary>
        /// The requests for a WebSocket the far end got, as they came.
        /// </summary>
        private readonly ConcurrentQueue<HttpListenerRequest>  dials   = new ();

        /// <summary>
        /// The frames the CSMS sent over the WebSocket it dialled.
        /// </summary>
        private readonly ConcurrentQueue<JArray>               frames  = new ();

        private WebSocket?                         line;

        #endregion

        #region (override) Configuration

        protected override JObject Configuration
            => new (
                   new JProperty("nts",  new JObject(new JProperty("groups", new JObject(new JProperty("legal", new JObject(new JProperty("enabled", false))))))),
                   // The name this CSMS comes under at what it dials: a local
                   // controller answers the node that asked, by that name.
                   new JProperty("ocpp", new JObject(new JProperty("nodeId", "csms-01"))),
                   new JProperty("ocppServer", new JObject(
                       new JProperty("enabled",           true),
                       new JProperty("address",           "127.0.0.1"),
                       new JProperty("port",              TestPorts.Free()),
                       new JProperty("securityProfiles",  new JArray(1)),
                       new JProperty("subprotocols",      new JArray("ocpp2.1")),
                       // What is said over a line this CSMS dialled is logged
                       // by the switch of the lines that dialled in.
                       new JProperty("logging",           new JObject(new JProperty("messages", true)))
                   ))
               );

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void ServeOCPPAsAStationDoes()
        {

            stop      = new CancellationTokenSource();
            port      = TestPorts.Free();
            listener  = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();

            dials. Clear();
            frames.Clear();
            line       = null;
            comesUnder = "csms-01";

            accepting = Task.Run(Accept);

        }

        [TearDown]
        public async Task ServeNoLonger()
        {

            stop.Cancel();

            try { line?.Abort(); }                            catch { }
            try { listener?.Stop(); listener?.Close(); }      catch { }
            try { if (accepting is not null) await accepting; } catch { }

            stop.Dispose();

        }

        #endregion

        #region (private) Accept() / Read(Socket) / Say(Frame)

        /// <summary>
        /// Take whoever signs in as "csms-01" with the password, and nobody
        /// else - as the OCPP server of a charging station takes whoever is
        /// written down as a connection the other end makes.
        /// </summary>
        private async Task Accept()
        {

            while (!stop.IsCancellationRequested)
            {

                HttpListenerContext context;

                try
                {
                    context = await listener!.GetContextAsync();
                }
                catch
                {
                    return;
                }

                dials.Enqueue(context.Request);

                var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{comesUnder}:{ThePassword}"));

                if (!context.Request.IsWebSocketRequest ||
                    context.Request.Url?.AbsolutePath != $"/{comesUnder}" ||
                    context.Request.Headers["Authorization"] != expected)
                {
                    context.Response.StatusCode = 401;
                    context.Response.Close();
                    continue;
                }

                var accepted = await context.AcceptWebSocketAsync("ocpp2.1");

                line = accepted.WebSocket;

                _ = Task.Run(() => Read(accepted.WebSocket));

            }

        }

        private async Task Read(WebSocket Socket)
        {

            var buffer = new Byte[1 << 16];

            try
            {

                while (!stop.IsCancellationRequested && Socket.State == WebSocketState.Open)
                {

                    var text = new StringBuilder();
                    WebSocketReceiveResult result;

                    do
                    {
                        result = await Socket.ReceiveAsync(buffer, stop.Token);
                        text.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                    }
                    while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Close)
                        return;

                    frames.Enqueue(JArray.Parse(text.ToString()));

                }

            }
            catch
            { }

        }

        private Task Say(JArray Frame)

            => line!.SendAsync(Encoding.UTF8.GetBytes(Frame.ToString(Newtonsoft.Json.Formatting.None)),
                               WebSocketMessageType.Text,
                               true,
                               stop.Token);

        #endregion

        #region (private) ALogin(Node, LocalController, Gateway) / ItsCredentials() / AConnection(...) / Until(Condition)

        private void ALogin(String Node, Boolean LocalController = false, Boolean Gateway = false)
        {

            Assert.That(CSMS.StationLogins.TrySetPassword(Node, null, null, null, out _, out var error), Is.True, error);

            if (LocalController)
                Assert.That(CSMS.StationLogins.TrySetLocalController(Node, true, out error), Is.True, error);

            if (Gateway)
                Assert.That(CSMS.StationLogins.TrySetGateway(Node, true, out error), Is.True, error);

        }

        private String ItsCredentials(String Password = ThePassword)
        {

            Assert.That(CSMS.Connections.TryAddAuthentication("What this CSMS signs in with", "basic", "csms-01", Password, out var id, out var error),
                        Is.True, error);

            return id!;

        }

        private String AConnection(String   Node,
                                   String   Type           = "ChargingStation",
                                   Boolean  AutoConnect    = true,
                                   String?  Credentials    = null)
        {

            Assert.That(CSMS.Connections.TryAddConnection($"The node '{Node}'", $"ws://127.0.0.1:{port}/csms-01", Type, AutoConnect,
                                                          Credentials ?? ItsCredentials(), null,
                                                          out var id, out var error,
                                                          RemoteNodeId: Node),
                        Is.True, error);

            return id!;

        }

        private static async Task<Boolean> Until(Func<Boolean> Condition, Int32 Seconds = 10)
        {

            for (var i = 0; i < Seconds * 20 && !Condition(); i++)
                await Task.Delay(50);

            return Condition();

        }

        #endregion


        #region What a CSMS writes down

        [Test]
        public async Task TheConnectionsOfACSMSLeadToWhatIsBelowIt()
        {

            using var http = await SignedIn();

            var json = await GetJSON(http, "api/v1/configuration/connections");

            Assert.Multiple(() => {
                Assert.That(json["connectionTypes"]!.Select(type => type.Value<String>()),
                            Is.EqualTo(new[] { "ChargingStation", "LocalController", "Gateway" }));
                Assert.That(json["ocppVersions"]!.Select(version => version.Value<String>()),
                            Is.EqualTo(new[] { "OCPP2.1" }));
                Assert.That(json["rules"]!.Value<Boolean>("inbound"),                Is.False);
                Assert.That(json["rules"]!.Value<Boolean>("ssh"),                    Is.False);
                Assert.That(json["rules"]!.Value<Boolean>("namesTheNodeItLeadsTo"),  Is.True);
            });

        }

        [Test]
        public void ANodeThatIsDialledIsALoginOfThisCSMS()
        {

            Assert.That(CSMS.Connections.TryAddConnection("A stranger", $"ws://127.0.0.1:{port}/csms-01", "ChargingStation", true, null, null,
                                                          out _, out var error,
                                                          RemoteNodeId: "cs404"),
                        Is.False);

            Assert.That(error, Does.Contain("is no login of this CSMS"));

        }

        [Test]
        public async Task AConnectionIsWrittenDownOverTheAPI()
        {

            ALogin("cs007");

            using var http = await SignedIn();

            var response = await http.PostAsync("api/v1/configuration/connections",
                                                JSONBody(new JProperty("description",     "Station 7"),
                                                         new JProperty("url",             $"ws://127.0.0.1:{port}/csms-01"),
                                                         new JProperty("connectionType",  "ChargingStation"),
                                                         new JProperty("ocppVersion",     "OCPP2.1"),
                                                         new JProperty("autoConnect",     false),
                                                         new JProperty("remoteNodeId",    "cs007")));

            Assert.That((Int32) response.StatusCode, Is.EqualTo(201), await response.Content.ReadAsStringAsync());

            Assert.That(CSMS.Connections.Connections.Single().RemoteNodeId, Is.EqualTo("cs007"));

            // And none over ssh://, none that is dialled, none in OCPP 1.6.
            var overSSH = await http.PostAsync("api/v1/configuration/connections",
                                               JSONBody(new JProperty("description",     "Station 7, over SSH"),
                                                        new JProperty("url",             "ssh://csms-01@127.0.0.1"),
                                                        new JProperty("connectionType",  "ChargingStation"),
                                                        new JProperty("remoteNodeId",    "cs007")));

            Assert.That((Int32) overSSH.StatusCode, Is.EqualTo(400));

        }

        #endregion

        #region What a CSMS dials

        [Test]
        public async Task ACSMSDialsAChargingStationAndSpeaksOCPPWithIt()
        {

            ALogin("cs007");
            AConnection("cs007");

            Assert.That(await Until(() => CSMS.IsConnected("cs007")), Is.True, "the station never counted as connected");

            // What the station saw of the dial: the name this CSMS comes
            // under, what it signed in with, OCPP 2.1 - and the plain frame.
            Assert.That(dials.TryPeek(out var dial), Is.True);

            Assert.Multiple(() => {
                Assert.That(dial!.Url!.AbsolutePath,                          Is.EqualTo("/csms-01"));
                Assert.That(dial.Headers["Sec-WebSocket-Protocol"],           Does.Contain("ocpp2.1"));
                Assert.That(dial.Headers["X-OCPP-NetworkingMode"] ?? "",      Does.Not.Contain("Overlay"));
                Assert.That(CSMS.ConnectedStations,                           Does.Contain("cs007"));
                Assert.That(CSMS.StationConnections.Single().Dialled,         Is.True);
            });

            // The station says that it started, as it says to a CSMS it
            // dialled - and is answered as the station 'cs007'.
            await Say(new JArray(2, "boot-1", "BootNotification", new JObject(
                          new JProperty("reason",           "PowerUp"),
                          new JProperty("chargingStation",  new JObject(
                              new JProperty("model",       "A model"),
                              new JProperty("vendorName",  "A vendor")
                          ))
                      )));

            Assert.That(await Until(() => frames.Any(frame => frame[0]!.Value<Int32>() == 3 && frame[1]!.Value<String>() == "boot-1")),
                        Is.True, "the BootNotification was never answered");

            // And the CSMS asks it, by its name.
            var asking = CSMS.InstalledOn("cs007");

            Assert.That(await Until(() => frames.Any(frame => frame[0]!.Value<Int32>() == 2 && frame[2]!.Value<String>() == "GetInstalledCertificateIds")),
                        Is.True, "the station was never asked");

            var asked = frames.First(frame => frame[0]!.Value<Int32>() == 2 && frame[2]!.Value<String>() == "GetInstalledCertificateIds");

            await Say(new JArray(3, asked[1]!.Value<String>(), new JObject(new JProperty("status", "NotFound"))));

            Assert.That((await asking).Asked, Is.True);

            // All of it in the log, under the name of the station, as what a
            // station that dialled in says is - and by name only: what the
            // messages carry is another switch.
            var said = CSMS.Log.Recent(500).Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(said, Has.Some.EqualTo("<- cs007: BootNotification [boot-1]"));
                Assert.That(said, Has.Some.StartsWith("-> cs007: GetInstalledCertificateIds ["));
                Assert.That(said.Count(line => line == "<- cs007: BootNotification [boot-1]"), Is.EqualTo(1));
            });

        }

        [Test]
        public async Task ALocalControllerIsDialledInTheOverlayNetwork()
        {

            ALogin("lc01", LocalController: true);
            AConnection("lc01", Type: "LocalController");

            Assert.That(await Until(() => CSMS.IsConnected("lc01")), Is.True, "the local controller never counted as connected");

            Assert.That(dials.TryPeek(out var dial), Is.True);

            Assert.Multiple(() => {
                Assert.That(dial!.Headers["X-OCPP-NetworkingMode"],  Is.EqualTo("OverlayNetwork"));
                Assert.That(CSMS.InOverlayNetwork("lc01"),           Is.True);
            });

        }

        [Test]
        public async Task AGatewayIsDialledInTheOverlayNetwork()
        {

            ALogin("gw01", Gateway: true);
            AConnection("gw01", Type: "Gateway");

            Assert.That(await Until(() => CSMS.IsConnected("gw01")), Is.True, "the gateway never counted as connected");

            Assert.That(dials.TryPeek(out var dial), Is.True);

            Assert.Multiple(() => {
                Assert.That(dial!.Headers["X-OCPP-NetworkingMode"],  Is.EqualTo("OverlayNetwork"));
                Assert.That(CSMS.InOverlayNetwork("gw01"),           Is.True);
                Assert.That(CSMS.Log.Recent(500).Select(entry => entry.Message),
                            Has.Some.StartsWith("The gateway 'gw01' is reached at"));
            });

        }

        [Test]
        public async Task ALocalControllerDialledUnderAnotherNameThanThisCSMSHasInOCPP_IsDialledAndWarnedOf()
        {

            comesUnder = "csms-02";

            ALogin("lc01", LocalController: true);

            Assert.That(CSMS.Connections.TryAddAuthentication("What this CSMS signs in with, as another", "basic", "csms-02", ThePassword, out var login, out var error),
                        Is.True, error);

            // Under another name than its own: a controller of today finds
            // the way back for its answers, an older one does not - so it is
            // dialled, and said.
            Assert.That(CSMS.Connections.TryAddConnection("The controller", $"ws://127.0.0.1:{port}/csms-02", "LocalController", true, login, null,
                                                          out var id, out error,
                                                          RemoteNodeId: "lc01"),
                        Is.True, error);

            Assert.That(await Until(() => CSMS.IsConnected("lc01")), Is.True, "the local controller never counted as connected");

            Assert.That(await Until(() => CSMS.ConnectionStates.TryGetValue(id!, out var state) && state.Said.Contains("make the two one")),
                        Is.True, CSMS.ConnectionStates.GetValueOrDefault(id!)?.Said);

            Assert.Multiple(() => {

                Assert.That(CSMS.WhyNotConnected(CSMS.Connections.Connections.Single(one => one.Id == id)),  Is.Null);
                Assert.That(CSMS.ConnectionStates[id!].Status,                                             Is.EqualTo(ConnectionStatus.Connected));
                Assert.That(CSMS.ConnectionStates[id!].Said,                                               Does.StartWith("Connected"));

                Assert.That(CSMS.Log.Recent(500).Where(entry => entry.Level == LogLevel.Warning).Select(entry => entry.Message),
                            Has.Some.Contains("'csms-02', the name this CSMS comes under at the local controller"));

            });

        }

        [Test]
        public async Task ALocalControllerDialledUnderTheNameThisCSMSHasInOCPP_IsNotWarnedOf()
        {

            ALogin("lc01", LocalController: true);
            var id = AConnection("lc01", "LocalController");

            Assert.That(await Until(() => CSMS.IsConnected("lc01")), Is.True, "the local controller never counted as connected");

            Assert.Multiple(() => {
                Assert.That(CSMS.WhyItsAnswersMayBeLost(CSMS.Connections.Connections.Single(one => one.Id == id)),  Is.Null);
                Assert.That(CSMS.ConnectionStates[id].Said,                                                         Does.Not.Contain("make the two one"));
            });

        }

        [Test]
        public async Task ALoginThatIsSwitchedOffIsNotDialled()
        {

            ALogin("cs007");

            Assert.That(CSMS.StationLogins.TrySetEnabled("cs007", false, out var error), Is.True, error);

            var id = AConnection("cs007");

            Assert.That(await Until(() => CSMS.ConnectionStates.ContainsKey(id)), Is.True);

            await Task.Delay(500);

            Assert.Multiple(() => {
                Assert.That(dials,                           Is.Empty);
                Assert.That(CSMS.IsConnected("cs007"),       Is.False);
                Assert.That(CSMS.ConnectionStates[id].Said,  Does.Contain("is switched off"));
            });

        }

        [Test]
        public async Task ALoginSwitchedOffWhileItIsDialledIsLetGoOfAndDialledAgainOnceItIsOn()
        {

            ALogin("cs007");
            AConnection("cs007");

            Assert.That(await Until(() => CSMS.IsConnected("cs007")), Is.True, "the station never counted as connected");

            Assert.That(CSMS.StationLogins.TrySetEnabled("cs007", false, out var error), Is.True, error);

            Assert.That(await Until(() => !CSMS.IsConnected("cs007")), Is.True, "a station whose login is switched off stayed connected");

            var dialledSoFar = dials.Count;

            Assert.That(CSMS.StationLogins.TrySetEnabled("cs007", true, out error), Is.True, error);

            Assert.That(await Until(() => CSMS.IsConnected("cs007")), Is.True, "a station whose login is on again was not dialled again");
            Assert.That(dials.Count, Is.GreaterThan(dialledSoFar));

        }

        [Test]
        public async Task WhatAConnectionSaysIsThereIsWhatItsLoginSays()
        {

            // A charging station, by its login - and a local controller, by
            // the connection.
            ALogin("cs007");

            var id = AConnection("cs007", Type: "LocalController");

            Assert.That(await Until(() => CSMS.ConnectionStates.ContainsKey(id)), Is.True);

            await Task.Delay(500);

            Assert.Multiple(() => {
                Assert.That(dials,                           Is.Empty);
                Assert.That(CSMS.ConnectionStates[id].Status, Is.EqualTo(ConnectionStatus.NotConnected));
                Assert.That(CSMS.ConnectionStates[id].Said,  Does.StartWith("Not connected: "));
                Assert.That(CSMS.ConnectionStates[id].Said,  Does.Contain("is not marked as one"));
            });

        }

        [Test]
        public async Task AGatewayIsNoLocalControllerToTheConnectionThatDialsIt()
        {

            // A local controller, by its login - and a gateway, by the
            // connection.
            ALogin("lc07", LocalController: true);

            var id = AConnection("lc07", Type: "Gateway");

            Assert.That(await Until(() => CSMS.ConnectionStates.ContainsKey(id)), Is.True);

            await Task.Delay(500);

            Assert.Multiple(() => {
                Assert.That(dials,                           Is.Empty);
                Assert.That(CSMS.ConnectionStates[id].Status, Is.EqualTo(ConnectionStatus.NotConnected));
                Assert.That(CSMS.ConnectionStates[id].Said,  Does.Contain("is marked as a local controller"));
                Assert.That(CSMS.ConnectionStates[id].Said,  Does.Contain("'gateways lc07 on'"));
            });

        }

        [Test]
        public async Task AWrongPasswordIsRefusedAndSaid()
        {

            ALogin("cs007");

            var id = AConnection("cs007", Credentials: ItsCredentials("not-the-password-of-this-station"));

            Assert.That(await Until(() => !dials.IsEmpty), Is.True, "nothing was dialled");

            Assert.That(await Until(() => CSMS.ConnectionStates.TryGetValue(id, out var state) &&
                                          state.Status != ConnectionStatus.Connected &&
                                          state.Said.Contains("401")),
                        Is.True, CSMS.ConnectionStates.GetValueOrDefault(id)?.Said);

            Assert.That(CSMS.IsConnected("cs007"), Is.False);

        }

        #endregion

        #region Who may send in whose name

        [Test]
        public async Task ALocalControllerThatIsDialledSpeaksForTheStationsBehindIt()
        {

            ALogin("lc01", LocalController: true);
            AConnection("lc01", Type: "LocalController");

            Assert.That(await Until(() => CSMS.IsConnected("lc01")), Is.True);

            // A station behind the controller says that it started: the
            // controller is the last hop of what it sends on.
            await Say(new JArray(2, "CSMS", new JArray("cs008", "lc01"), "boot-2", "BootNotification", new JObject(
                          new JProperty("reason",           "PowerUp"),
                          new JProperty("chargingStation",  new JObject(
                              new JProperty("model",       "A model"),
                              new JProperty("vendorName",  "A vendor")
                          ))
                      )));

            Assert.That(await Until(() => frames.Any(frame => frame[0]!.Value<Int32>() == 3 && frame.Any(part => part.Type == JTokenType.String && part.Value<String>() == "boot-2"))),
                        Is.True, "the BootNotification of the station behind the controller was never answered");

            // Reached over the line to the controller from then on: the one
            // client this CSMS made for it, which has one far end.
            Assert.That(CSMS.Node.Routing.LookupNetworkingNode(NetworkingNode_Id.Parse("cs008"), out var reachability) &&
                        reachability?.Client is not null,
                        Is.True, "the station behind the controller is not reached through it");

            // And what names another node as its last hop is dropped, over a
            // line this CSMS dialled as over one that was dialled in.
            await Say(new JArray(2, "CSMS", new JArray("cs009", "cs010"), "boot-3", "BootNotification", new JObject(
                          new JProperty("reason",           "PowerUp"),
                          new JProperty("chargingStation",  new JObject(
                              new JProperty("model",       "A model"),
                              new JProperty("vendorName",  "A vendor")
                          ))
                      )));

            await Task.Delay(1000);

            Assert.That(frames.Any(frame => frame.Any(part => part.Type == JTokenType.String && part.Value<String>() == "boot-3")),
                        Is.False, "what named another node as its last hop was answered");

        }

        #endregion

    }

}
