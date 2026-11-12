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
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.CommandLine;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The key pins of the stations behind a local controller, handed out by the CSMS over the controller's
    /// line in the overlay network (white paper "Key Pins and TLS 1.3 Raw Public Keys for Local Controllers",
    /// sections 5.5 to 5.7, work package K4, phase B3): a pin learned on first use confirmed with the
    /// controller's real pins, and a rollover in its order - and the command line and the API around both.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The local controller lc001 and the station cs001 behind it are one plain WebSocket that dials the CSMS
    /// in the overlay network - X-OCPP-NetworkingMode: OverlayNetwork - and answers what is addressed to either
    /// as each of them would: the controller its EVQICtrlr[TLSServer], the station its TLSClientController,
    /// whose pin sets it takes only where they verify as a station verifies them - by the CSMS's public key, for
    /// cs001, without a time window - and only with a higher version. What the CSMS asked of whom, in its
    /// order, is kept.
    /// </para>
    /// <para>
    /// The whole chain with a real controller and a real station is phase C, in EVChargingTestEnvironment.
    /// </para>
    /// </remarks>
    public class KeyPinsOverOCPPTests : ACSMSTests
    {

        #region (class) Controller

        /// <summary>
        /// A local controller and the station cs001 behind it, as one WebSocket in the overlay network.
        /// </summary>
        internal sealed class Controller : IAsyncDisposable
        {

            public const String  StationId  = "cs001";
            public const String  Endpoint   = "lc";

            /// <summary>
            /// The SSH key the station signs in to the controller with before its next one.
            /// </summary>
            public const String  OldSSHKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldOldOldOldOldOldOldOldOldOldOldOldOld cs001";

            private readonly ClientWebSocket                                         socket    = new ();
            private readonly CancellationTokenSource                                 stop      = new ();
            private readonly SemaphoreSlim                                           sending   = new (1, 1);
            private readonly ConcurrentDictionary<String, TaskCompletionSource<JArray>>  waiting   = new ();
            private          Task?                                                   loop;
            private          Int32                                                   lastId;

            public String   Id                  { get; }

            /// <summary>
            /// What the CSMS asked, in its order: of whom, what, with what, under which id.
            /// </summary>
            public ConcurrentQueue<(String Destination, String Action, JObject Payload)>  Asked  { get; } = new ();

            /// <summary>
            /// Whom each request of the CSMS named as where it comes from - empty where it named nobody.
            /// </summary>
            public ConcurrentQueue<(String Action, String From)>  AskedBy  { get; } = new ();

            #region The controller

            public KeyPin   Current             { get; set; } = APin();
            public KeyPin?  Next                { get; set; } = APin();

            #endregion

            #region The station

            /// <summary>
            /// The public key the station believes pin sets of: the CSMS's, given at commissioning - or none.
            /// </summary>
            public String?        PinSetSigner        { get; set; }

            public List<KeyPin>   StationPins         { get; set; } = [];
            public UInt64         StationVersion      { get; set; } = 3;
            public KeyPin?        Learned             { get; set; }
            public String         State               { get; set; } = "Configured";

            /// <summary>
            /// Whether the station reports pins without the next key's, whatever it was handed.
            /// </summary>
            public Boolean        LosesTheNextPin     { get; set; }

            /// <summary>
            /// The pin sets the station took: version and pins.
            /// </summary>
            public ConcurrentQueue<(UInt64 Version, String Pins)>  Taken     { get; } = new ();

            /// <summary>
            /// Why the station refused pin sets.
            /// </summary>
            public ConcurrentQueue<String>                         Refused   { get; } = new ();

            #endregion

            private Controller(String Id)
            {
                this.Id = Id;
            }

            #region Connect(Port, Password, Id, Overlay)

            public static async Task<Controller> Connect(UInt16   Port,
                                                         String   Password,
                                                         String   Id       = "lc001",
                                                         Boolean  Overlay  = true)
            {

                var controller = new Controller(Id);

                controller.socket.Options.AddSubProtocol("ocpp2.1");
                controller.socket.Options.SetRequestHeader("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Id}:{Password}")));

                if (Overlay)
                    controller.socket.Options.SetRequestHeader("X-OCPP-NetworkingMode", "OverlayNetwork");

                await controller.socket.ConnectAsync(new Uri($"ws://127.0.0.1:{Port}"), CancellationToken.None);

                controller.loop = Task.Run(controller.Receive);

                return controller;

            }

            #endregion

            #region AsStation(Action, Payload) / AsController(Action, Payload)

            /// <summary>
            /// A request of the station, sent up through the controller, as the controller sends it: its
            /// network path the station and the controller.
            /// </summary>
            public Task<JArray> AsStation(String Action, JObject Payload)
                => Ask(new JArray(StationId, Id), Action, Payload);

            public Task<JArray> AsController(String Action, JObject Payload)
                => Ask(Id, Action, Payload);

            /// <summary>
            /// A request in the station's name, sent up as <see cref="AsStation"/> sends it, but not waited
            /// for: its answer goes to the station, by the CSMS's route to it - which need not be this node.
            /// </summary>
            public Task TellAsStation(String Action, JObject Payload)
                => TellAs(new JArray(StationId, Id), Action, Payload);

            /// <summary>
            /// A request under whatever network path it is given, not waited for.
            /// </summary>
            public Task TellAs(JToken Path, String Action, JObject Payload)
                => Send(new JArray(2, "CSMS", Path, $"{Id}-{Interlocked.Increment(ref lastId)}", Action, Payload));

            /// <summary>
            /// A request under whatever network path it is given, and its answer - or null where none
            /// came within the given time.
            /// </summary>
            public async Task<JArray?> AskAs(JToken Path, String Action, JObject Payload, TimeSpan Within)
            {

                var id      = $"{Id}-{Interlocked.Increment(ref lastId)}";
                var answer  = new TaskCompletionSource<JArray>(TaskCreationOptions.RunContinuationsAsynchronously);

                waiting[id] = answer;

                await Send(new JArray(2, "CSMS", Path, id, Action, Payload));

                return await Task.WhenAny(answer.Task, Task.Delay(Within)) == answer.Task
                           ? await answer.Task
                           : null;

            }

            private async Task<JArray> Ask(JToken Path, String Action, JObject Payload)
            {

                var id      = $"{Id}-{Interlocked.Increment(ref lastId)}";
                var answer  = new TaskCompletionSource<JArray>(TaskCreationOptions.RunContinuationsAsynchronously);

                waiting[id] = answer;

                await Send(new JArray(2, "CSMS", Path, id, Action, Payload));

                if (await Task.WhenAny(answer.Task, Task.Delay(TimeSpan.FromSeconds(30))) != answer.Task)
                    Assert.Fail($"The CSMS did not answer {Action} {id}.");

                return await answer.Task;

            }

            #endregion

            #region (private) Receive()

            private async Task Receive()
            {

                var buffer = new Byte[1 << 16];

                try
                {

                    while (!stop.IsCancellationRequested && socket.State == WebSocketState.Open)
                    {

                        var text = new StringBuilder();
                        WebSocketReceiveResult result;

                        do
                        {
                            result = await socket.ReceiveAsync(buffer, stop.Token);
                            text.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                        }
                        while (!result.EndOfMessage);

                        if (result.MessageType == WebSocketMessageType.Close)
                            return;

                        JArray frame;

                        using (var reader = new JsonTextReader(new StringReader(text.ToString())) { DateParseHandling = DateParseHandling.None })
                            frame = JArray.Load(reader);

                        switch (frame[0].Value<Int32>())
                        {

                            // [2, destination, source, id, action, payload]
                            case 2 when frame.Count == 6:
                                try
                                {
                                    await Answer(frame[1].Value<String>() ?? "", frame[2], frame[3].Value<String>() ?? "", frame[4].Value<String>() ?? "", frame[5] as JObject ?? []);
                                }
                                catch (Exception e)
                                {
                                    // Said, and the next frame read: one that throws here
                                    // would otherwise end the line without a word.
                                    Failures.Enqueue($"{frame[4]} to {frame[1]}: {e.Message}");
                                }
                                break;

                            // [3, destination, path, id, payload]
                            case 3 when frame.Count == 5:
                            case 4 when frame.Count == 7:
                                if (waiting.TryRemove(frame[3].Value<String>() ?? "", out var answer))
                                    answer.TrySetResult(frame);
                                break;

                        }

                    }

                }
                catch (Exception) when (stop.IsCancellationRequested)
                { }
                catch (WebSocketException)
                { }

            }

            #endregion

            #region (private) Answer(Destination, Source, Id, Action, Payload)

            private async Task Answer(String   Destination,
                                      JToken   Source,
                                      String   Id,
                                      String   Action,
                                      JObject  Payload)
            {

                Asked.Enqueue((Destination, Action, Payload));

                var from = Source is JArray path
                               ? path.FirstOrDefault()?.Value<String>() ?? ""
                               : Source.Value<String>() ?? "";

                AskedBy.Enqueue((Action, from));

                // A request that names nobody it comes from cannot be answered
                // to anybody: refused, as a controller's node refuses it.
                if (from.Length == 0)
                {
                    await Send(new JArray(4, "CSMS", this.Id, Id, "FormatViolation", "The request names no source.", new JObject()));
                    return;
                }

                if (Destination == this.Id)
                {
                    await Send(new JArray(3, from, this.Id, Id, AsTheController(Action, Payload)));
                    return;
                }

                if (Destination == StationId)
                {

                    await Send(new JArray(3, from, new JArray(StationId, this.Id), Id, AsTheStation(Action, Payload, Id)));

                    // The report follows the answer to GetReport.
                    if (Action == "GetReport")
                        _ = Task.Run(() => AsStation("NotifyReport", new JObject(
                                                         new JProperty("requestId",    Payload["requestId"]),
                                                         new JProperty("seqNo",        0),
                                                         new JProperty("generatedAt",  DateTimeOffset.UtcNow.ToString("o")),
                                                         new JProperty("tbc",          false),
                                                         new JProperty("reportData",   new JArray(Report()))
                                                     )));

                }

            }

            #endregion

            #region (private) AsTheController(Action, Payload)

            private JObject AsTheController(String   Action,
                                            JObject  Payload)
            {

                if (Action == "GetVariables")
                    return new JObject(new JProperty("getVariableResult", new JArray(
                               (Payload["getVariableData"] as JArray ?? []).OfType<JObject>().Select(data => new JObject(
                                   new JProperty("attributeStatus",  "Accepted"),
                                   new JProperty("attributeValue",   (data["variable"]?["name"]?.Value<String>()) switch {
                                                                          "ActiveKeyPin"  => Current.ToHex(),
                                                                          "NextKeyPin"    => Next?.ToHex() ?? "",
                                                                          "KeyPins"       => String.Join(",", new[] { Current, Next }.OfType<KeyPin>().Select(pin => pin.ToHex())),
                                                                          "KeyCreated"    => "2026-10-01T00:00:00.000Z",
                                                                          _               => ""
                                                                      }),
                                   new JProperty("component",        data["component"]),
                                   new JProperty("variable",         data["variable"])
                               ))
                           )));

                // The SSH keys of its stations: the station's one old key listed, the next one installed, the
                // old one deleted.
                if (Action == "GetInstalledSSHKeys")
                    return new JObject(new JProperty("status", "Accepted"),
                                       new JProperty("keys",   new JArray(new JObject(
                                           new JProperty("networkingNodeId",  StationId),
                                           new JProperty("purpose",           "OCPP"),
                                           new JProperty("publicKey",         OldSSHKey),
                                           new JProperty("keyFingerprint",    "SHA256:old")
                                       ))));

                if (Action is "InstallSSHKey" or "DeleteSSHKey")
                    return new JObject(new JProperty("status", "Accepted"));

                if (Action == "SetVariables")
                    return new JObject(new JProperty("setVariableResult", new JArray(
                               (Payload["setVariableData"] as JArray ?? []).OfType<JObject>().Select(data => {

                                   var switched = data["variable"]?["name"]?.Value<String>() == "ActiveKeyPin" &&
                                                  Next is not null &&
                                                  data["attributeValue"]?.Value<String>() == Next.ToHex();

                                   if (switched)
                                   {
                                       Current = Next!;
                                       Next    = null;
                                   }

                                   return new JObject(
                                              new JProperty("attributeStatus",  switched ? "Accepted" : "Rejected"),
                                              new JProperty("component",        data["component"]),
                                              new JProperty("variable",         data["variable"])
                                          );

                               })
                           )));

                return [];

            }

            #endregion

            #region (private) AsTheStation(Action, Payload, Id)

            private JObject AsTheStation(String   Action,
                                         JObject  Payload,
                                         String   Id)
            {

                switch (Action)
                {

                    case "GetReport":
                    case "SSHKeySigned":
                        return new JObject(new JProperty("status", "Accepted"));

                    case "GetVariables":
                        return new JObject(new JProperty("getVariableResult", new JArray(
                                   (Payload["getVariableData"] as JArray ?? []).OfType<JObject>().Select(data => new JObject(
                                       new JProperty("attributeStatus",  "Accepted"),
                                       new JProperty("attributeValue",   data["variable"]?["name"]?.Value<String>() == "ServerKeyPins"
                                                                             ? String.Join(",", StationPins.Where (pin => !LosesTheNextPin || pin != Next).
                                                                                                            Select(pin => pin.ToHex()))
                                                                             : ""),
                                       new JProperty("component",        data["component"]),
                                       new JProperty("variable",         data["variable"])
                                   ))
                               )));

                    case "SetVariables":
                        return new JObject(new JProperty("setVariableResult", new JArray(TakePinSet(Payload, Id))));

                    default:
                        return [];

                }

            }

            /// <summary>
            /// A pin set, taken as the station takes one: verified by the key it believes, for cs001, without the
            /// time window - and only with a higher version.
            /// </summary>
            private IEnumerable<JObject> TakePinSet(JObject  Payload,
                                                    String   Id)
            {

                var entries  = (Payload["setVariableData"] as JArray ?? []).OfType<JObject>().ToArray();

                IEnumerable<JObject> All(String Status, String? Reason = null)

                    => entries.Select(data => {

                           var result = new JObject(
                                            new JProperty("attributeStatus",  Status),
                                            new JProperty("component",        data["component"]),
                                            new JProperty("variable",         data["variable"])
                                        );

                           if (Reason is not null)
                               result.Add("attributeStatusInfo", new JObject(new JProperty("reasonCode", Reason)));

                           return result;

                       });

                if (PinSetSigner is null)
                {
                    Refused.Enqueue("Unsigned: no signer believed");
                    return All("Rejected", "Unsigned");
                }

                var request = AsTheStationChecks.Received(Payload, Id, StationId);

                if (!AsTheStationChecks.Verifies(request, PinSetSigner, StationId, WithoutTimeWindow: true, out var error))
                {
                    Refused.Enqueue($"Unsigned: {error}");
                    return All("Rejected", "Unsigned");
                }

                var values   = entries.ToDictionary(data => data["variable"]?["name"]?.Value<String>() ?? "",
                                                    data => data["attributeValue"]?.Value<String>() ?? "");

                if (entries.Any(data => data["component"]?["name"]?.Value<String>() != "TLSClientController" ||
                                        data["component"]?["instance"]?.Value<String>() != Endpoint) ||
                    !values.TryGetValue("ServerKeyPins", out var pins) ||
                    !values.TryGetValue("ServerKeyPinsVersion", out var versionText) ||
                    !UInt64.TryParse(versionText, out var version))
                {
                    Refused.Enqueue("InvalidValue: not a pin set of the endpoint");
                    return All("Rejected", "InvalidValue");
                }

                if (version <= StationVersion)
                {
                    Refused.Enqueue($"InvalidValue: version {version} is not above {StationVersion}");
                    return All("Rejected", "InvalidValue");
                }

                StationPins     = [.. pins.Split(',').Select(KeyPin.Parse)];
                StationVersion  = version;

                if (Learned is not null)
                {
                    State    = StationPins.Contains(Learned) ? "Confirmed" : "Configured";
                    Learned  = null;
                }

                Taken.Enqueue((version, pins));

                return All("Accepted");

            }

            /// <summary>
            /// The station's report of TLSClientController: its endpoint to the controller, and one straight to
            /// the CSMS beside it.
            /// </summary>
            private IEnumerable<JObject> Report()
            {

                static JObject Data(String Instance, String Variable, String Value)

                    => new (
                           new JProperty("component",          new JObject(new JProperty("name", "TLSClientController"), new JProperty("instance", Instance))),
                           new JProperty("variable",           new JObject(new JProperty("name", Variable))),
                           new JProperty("variableAttribute",  new JArray(new JObject(new JProperty("type", "Actual"), new JProperty("value", Value))))
                       );

                yield return Data(Endpoint, "ServerKeyPins",         String.Join(",", StationPins.Select(pin => pin.ToHex())));
                yield return Data(Endpoint, "ServerKeyPinsVersion",  StationVersion.ToString());
                yield return Data(Endpoint, "ServerKeyPinState",     Learned is not null ? "Learned" : State);
                yield return Data(Endpoint, "LearnedKeyPin",         Learned?.ToHex() ?? "");
                yield return Data(Endpoint, "KeyPinShown",           (Learned ?? Current).ToHex());
                yield return Data(Endpoint, "URL",                   $"wss://{Id}.local/{StationId}");

                yield return Data("csms",   "ServerKeyPins",         "");
                yield return Data("csms",   "ServerKeyPinsVersion",  "0");
                yield return Data("csms",   "ServerKeyPinState",     "Configured");
                yield return Data("csms",   "URL",                   $"wss://csms.example.org/{StationId}");

            }

            #endregion

            #region (private) Send(Frame)

            /// <summary>
            /// What went wrong answering the CSMS.
            /// </summary>
            public ConcurrentQueue<String> Failures  { get; } = new ();

            private async Task Send(JArray Frame)
            {

                await sending.WaitAsync();

                try
                {
                    await socket.SendAsync(Encoding.UTF8.GetBytes(Frame.ToString(Formatting.None)), WebSocketMessageType.Text, true, CancellationToken.None);
                }
                finally
                {
                    sending.Release();
                }

            }

            #endregion

            public async ValueTask DisposeAsync()
            {

                stop.Cancel();

                try { socket.Abort(); }                    catch { }
                try { if (loop is not null) await loop; }  catch { }

                socket.Dispose();
                stop.  Dispose();

            }

        }

        #endregion

        #region Data

        private const String ThePassword = "a-password-long-enough-for-ocpp";

        private Controller                    lc      = default!;
        private readonly ConcurrentQueue<String>  said    = new ();

        private static readonly TimeSpan      Patience  = TimeSpan.FromSeconds(15);

        #endregion

        #region (override) Configuration

        /// <summary>
        /// A CSMS whose charging station server is switched on, on the loopback address, over security profile 1.
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
        /// The controller lc001, connected in the overlay network, and the station cs001 behind it booted.
        /// </summary>
        [SetUp]
        public async Task ConnectTheControllerAndBootTheStation()
        {

            said.Clear();

            CSMS.Log.OnLogged += entry => said.Enqueue(entry.Message);

            lc = await AController("lc001", Overlay: true);

            var boot = await lc.AsStation("BootNotification", new JObject(
                                              new JProperty("chargingStation", new JObject(
                                                  new JProperty("model",       "Bay"),
                                                  new JProperty("vendorName",  "GraphDefined")
                                              )),
                                              new JProperty("reason", "PowerUp")
                                          ));

            Assert.That(boot[4]?["status"]?.Value<String>(), Is.EqualTo("Accepted"), boot.ToString(Formatting.None));

            await Until(() => CSMS.KeyPins.LocalControllerOf(Controller.StationId) is not null, "the CSMS noting the station behind its controller");

        }

        [TearDown]
        public async Task DisconnectTheController()
        {

            if (lc is null)
                return;

            var failures = lc.Failures.ToArray();

            await lc.DisposeAsync();

            // A controller that could not answer what it was asked is no
            // controller the test can be about.
            Assert.That(failures, Is.Empty, "The test's controller could not answer the CSMS.");

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// A local controller, its login marked as one: which may send in the name of the stations behind it.
        /// </summary>
        private async Task<Controller> AController(String   Id,
                                                   Boolean  Overlay)
        {

            Assert.That(CSMS.StationLogins.TrySetPassword        (Id, ThePassword, null, null, out _, out var error), Is.True, error);
            Assert.That(CSMS.StationLogins.TrySetLocalController(Id, true, out var markError),                     Is.True, markError);

            var controller = await Controller.Connect(CSMS.OCPPServerSettings.TCPPort!.Value.ToUInt16(), ThePassword, Id, Overlay);

            await Until(() => CSMS.IsConnected(Id), $"'{Id}' counting as connected");

            return controller;

        }

        private String ASigningKey()
        {

            Assert.That(CSMS.PinSetSigner.TryCreate("test", out var publicKey, out var error), Is.True, error);

            return publicKey!;

        }

        private static KeyPin APin()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return KeyPin.FromKey(key);
        }

        private static async Task Until(Func<Boolean> Condition, String What)
        {

            var giveUp = DateTimeOffset.UtcNow + Patience;

            while (!Condition() && DateTimeOffset.UtcNow < giveUp)
                await Task.Delay(20);

            Assert.That(Condition(), Is.True, $"Waited in vain for {What}.");

        }

        /// <summary>
        /// The station's KeyPinLearned for its endpoint to the controller, as the station words it.
        /// </summary>
        private Task<JArray> KeyPinLearned(KeyPin Learned)

            => lc.AsStation("SecurityEventNotification", new JObject(
                                new JProperty("type",       "KeyPinLearned"),
                                new JProperty("timestamp",  DateTimeOffset.UtcNow.ToString("o")),
                                new JProperty("techInfo",   $"Key pin {Learned.ToHex()} of endpoint '{Controller.Endpoint}' (wss://lc001.local/cs001) learned on first use, on probation")
                            ));

        /// <summary>
        /// Where in what the CSMS asked the given request is: its index, or -1.
        /// </summary>
        private Int32 IndexOf(String Destination, String Action, Func<JObject, Boolean>? Wanted = null)
        {

            var asked = lc.Asked.ToArray();

            for (var i = 0; i < asked.Length; i++)
                if (asked[i].Destination == Destination && asked[i].Action == Action && (Wanted is null || Wanted(asked[i].Payload)))
                    return i;

            return -1;

        }

        private String Asked
            => String.Join(" | ", lc.Asked.Select(asked => $"{asked.Destination} {asked.Action}")) +
               (lc.Failures.IsEmpty ? "" : $" - and it failed: {String.Join("; ", lc.Failures)}");

        private String Log
            => String.Join(Environment.NewLine, said);

        private static JObject ABootNotification()

            => new (
                   new JProperty("chargingStation", new JObject(
                       new JProperty("model",       "Bay"),
                       new JProperty("vendorName",  "GraphDefined")
                   )),
                   new JProperty("reason", "PowerUp")
               );

        /// <summary>
        /// The node the CSMS routes the given station through.
        /// </summary>
        private String? RouteOf(String Station)

            => CSMS.Node.Routing.LookupNetworkingNode(NetworkingNode_Id.Parse(Station), out var reachability)
                   ? reachability?.NetworkingHub?.ToString() ?? reachability?.DestinationId.ToString()
                   : null;

        private static Func<JObject, Boolean> PinsAre(params KeyPin[] Pins)

            => payload => (payload["setVariableData"] as JArray ?? []).OfType<JObject>().
                              Any(data => data["variable"]?["name"]?.Value<String>() == "ServerKeyPins" &&
                                          data["attributeValue"]?.Value<String>() == String.Join(",", Pins.Select(pin => pin.ToHex())));

        #endregion


        #region AStationBehindAController_IsNotedFromItsBootNotification()

        /// <summary>
        /// A station whose BootNotification came through a controller in the overlay network is noted behind
        /// it, with a route to it through the controller.
        /// </summary>
        [Test]
        public void AStationBehindAController_IsNotedFromItsBootNotification()
        {

            Assert.Multiple(() => {
                Assert.That(CSMS.KeyPins.LocalControllerOf(Controller.StationId),  Is.EqualTo("lc001"));
                Assert.That(CSMS.InOverlayNetwork("lc001"),                        Is.True);
                Assert.That(CSMS.Node.Routing.LookupNetworkingNode(NetworkingNode_Id.Parse(Controller.StationId), out var reachability), Is.True);
                Assert.That(reachability?.NetworkingHub?.ToString() ?? reachability?.DestinationId.ToString(),
                                                                                   Is.EqualTo("lc001"), "the route to the station does not go through its controller");
            });

        }

        #endregion

        #region AnotherNode_NamingItselfTheWayToAStation_DoesNotTakeItOver()

        /// <summary>
        /// Another local controller names itself the last hop of a station behind this one - which a controller
        /// may, sending in the name of the stations behind it, and which no frame can be told wrong by. A station
        /// noted behind its controller stays there: its route is not moved, and the log says who tried. (A
        /// station that is no controller does not get this far: OverlaySenderTests.)
        /// </summary>
        [Test]
        public async Task AnotherNode_NamingItselfTheWayToAStation_DoesNotTakeItOver()
        {

            await using var impostor = await AController("lc007", Overlay: true);

            await impostor.TellAsStation("BootNotification", ABootNotification());

            // Taken over, or the CSMS saying it is not.
            await Until(() => CSMS.KeyPins.Get("lc007") is not null || Log.Contains("'lc007' names itself the way"),
                        "the CSMS taking in what 'lc007' named itself");

            Assert.Multiple(() => {
                Assert.That(CSMS.KeyPins.LocalControllerOf(Controller.StationId),  Is.EqualTo("lc001"), Log);
                Assert.That(CSMS.KeyPins.Get("lc007"),                             Is.Null, "'lc007' was taken for a controller");
                Assert.That(RouteOf(Controller.StationId),                         Is.EqualTo("lc001"), "the route to the station was moved");
                Assert.That(said.Any(line => line.Contains("'lc007'") && line.Contains("'lc001'")),
                                                                                   Is.True, Log);
            });

        }

        #endregion

        #region AKeyPinLearned_ThroughAnotherNode_IsNotConfirmed()

        /// <summary>
        /// A KeyPinLearned in a station's name, sent up by another local controller than the station's: no pin
        /// set is signed for it - not of that node's pins, which the CSMS would otherwise read and sign as the
        /// controller's, and not of the controller's either.
        /// </summary>
        [Test]
        public async Task AKeyPinLearned_ThroughAnotherNode_IsNotConfirmed()
        {

            var signer             = ASigningKey();

            lc.PinSetSigner        = signer;

            await using var impostor = await AController("lc007", Overlay: true);

            impostor.PinSetSigner  = signer;
            impostor.Learned       = impostor.Current;

            await impostor.TellAsStation("SecurityEventNotification", new JObject(
                                             new JProperty("type",       "KeyPinLearned"),
                                             new JProperty("timestamp",  DateTimeOffset.UtcNow.ToString("o")),
                                             new JProperty("techInfo",   $"Key pin {impostor.Current.ToHex()} of endpoint '{Controller.Endpoint}' (wss://lc001.local/cs001) learned on first use, on probation")
                                         ));

            await Until(() => !impostor.Taken.IsEmpty || !lc.Taken.IsEmpty || Log.Contains("through 'lc007'"),
                        "a pin set, or the CSMS saying it sends none");

            // Whatever was under way, given its time.
            await Task.Delay(500);

            Assert.Multiple(() => {
                Assert.That(impostor.Taken,                                   Is.Empty, "a pin set of the impostor's pins went to the impostor");
                Assert.That(impostor.Asked.Select(asked => $"{asked.Destination} {asked.Action}"),
                                                                              Is.Empty, "the impostor was asked as a controller");
                Assert.That(lc.Taken,                                         Is.Empty, "a pin set went to the station all the same");
                Assert.That(CSMS.KeyPins.LocalControllerOf(Controller.StationId), Is.EqualTo("lc001"));
                Assert.That(Log,                                              Does.Contain("through 'lc007'"));
            });

        }

        #endregion

        #region AStationThatMoved_IsForgotten_AndNotedBehindItsNewController()

        /// <summary>
        /// A station that really moved to another controller is forgotten by hand - at the console, not by a
        /// cpo: where a station is decides where its pin sets go - and its next BootNotification through the
        /// new controller notes it there, with its route.
        /// </summary>
        [Test]
        public async Task AStationThatMoved_IsForgotten_AndNotedBehindItsNewController()
        {

            using var console  = Console();
            using var cpo      = await OverSSHAs("carla", "cpo");

            var cpoForget      = await Run(cpo,     "keyPins forget cs001");
            var stays          = CSMS.KeyPins.LocalControllerOf(Controller.StationId);
            var forgotten      = await Run(console, "keyPins forget cs001");
            var unknown        = await Run(console, "keyPins forget cs001");
            var unrouted       = RouteOf(Controller.StationId);

            await using var next = await AController("lc002", Overlay: true);

            await next.AsStation("BootNotification", ABootNotification());

            await Until(() => CSMS.KeyPins.LocalControllerOf(Controller.StationId) == "lc002", "the station noted behind its new controller");

            Assert.Multiple(() => {
                Assert.That(cpoForget,                     Does.Contain("'carla' may not do that here"));
                Assert.That(stays,                         Is.EqualTo("lc001"), "a cpo's 'forget' was carried out");
                Assert.That(forgotten,                     Does.Contain("cs001").And.Contain("lc001").And.Contain("forgotten"));
                Assert.That(unknown,                       Does.Contain("not known"));
                Assert.That(unrouted,                      Is.Null, "the route through the controller it left is still there");
                Assert.That(RouteOf(Controller.StationId), Is.EqualTo("lc002"));
            });

        }

        #endregion

        #region AStationThatMoved_IsForgotten_ByTheAPI_AtTheCertificatesPermission()

        /// <summary>
        /// DELETE /api/v1/key-pins/stations/{station}: refused to a cpo, done for an administrator, and 404 for
        /// a station not known behind a controller.
        /// </summary>
        [Test]
        public async Task AStationThatMoved_IsForgotten_ByTheAPI_AtTheCertificatesPermission()
        {

            var (_, cpoPassword) = await AnAccount("carla", "cpo");

            var admin            = await SignedIn();
            var cpo              = await SignedInAs("carla", cpoPassword);

            var cpoForget        = await cpo.  DeleteAsync("/api/v1/key-pins/stations/cs001");
            var stays            = CSMS.KeyPins.LocalControllerOf(Controller.StationId);
            var forgotten        = await admin.DeleteAsync("/api/v1/key-pins/stations/cs001");
            var unknown          = await admin.DeleteAsync("/api/v1/key-pins/stations/cs001");

            Assert.Multiple(() => {
                Assert.That(cpoForget.StatusCode,                                 Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(stays,                                                Is.EqualTo("lc001"));
                Assert.That(forgotten.StatusCode,                                 Is.EqualTo(HttpStatusCode.OK));
                Assert.That(CSMS.KeyPins.LocalControllerOf(Controller.StationId), Is.Null);
                Assert.That(RouteOf(Controller.StationId),                        Is.Null);
                Assert.That(unknown.StatusCode,                                   Is.EqualTo(HttpStatusCode.NotFound));
            });

        }

        #endregion

        #region AKeyPinLearned_IsConfirmed_WithTheControllersPins()

        /// <summary>
        /// A station behind the controller that learned the controller's key pin on first use is handed the
        /// controller's pins as the controller reports them - current and next - signed, with the version above
        /// the one it holds: the CSMS reads the controller's pins, then the station's report, then sends the pin
        /// set, which the station verifies and takes. Nothing is asked of the controller beyond its pins.
        /// </summary>
        [Test]
        public async Task AKeyPinLearned_IsConfirmed_WithTheControllersPins()
        {

            lc.PinSetSigner  = ASigningKey();
            lc.Learned       = lc.Current;

            await KeyPinLearned(lc.Current);

            await Until(() => !lc.Taken.IsEmpty || !lc.Refused.IsEmpty, "a pin set reaching the station");

            var readPins   = IndexOf("lc001",                "GetVariables");
            var report     = IndexOf(Controller.StationId,   "GetReport");
            var pinSet     = IndexOf(Controller.StationId,   "SetVariables");

            await Until(() => CSMS.KeyPins.StationOf(Controller.StationId)?.Accepted == true, "the CSMS noting the pin set taken");

            var noted = CSMS.KeyPins.StationOf(Controller.StationId);

            Assert.Multiple(() => {

                Assert.That(lc.Refused,                       Is.Empty, $"the station refused the pin set: {String.Join("; ", lc.Refused)}");
                Assert.That(lc.Taken.Select(taken => taken.Version), Is.EqualTo(new[] { 4UL }), "not one pin set of the version above the station's");
                Assert.That(lc.Taken.FirstOrDefault().Pins,   Is.EqualTo($"{lc.Current.ToHex()},{lc.Next!.ToHex()}"), "not the controller's pins, current first");
                Assert.That(lc.State,                         Is.EqualTo("Confirmed"));

                Assert.That(readPins,                         Is.GreaterThanOrEqualTo(0),  Asked);
                Assert.That(report,                           Is.GreaterThan(readPins),    $"the station's report was not asked for after the controller's pins: {Asked}");
                Assert.That(pinSet,                           Is.GreaterThan(report),      $"the pin set was not sent after the report: {Asked}");
                Assert.That(IndexOf("lc001", "SetVariables"), Is.EqualTo(-1),              $"the controller was told to switch: {Asked}");

                Assert.That(noted?.Connection,                Is.EqualTo(Controller.Endpoint));
                Assert.That(noted?.Version,                   Is.EqualTo(4));
                Assert.That(CSMS.KeyPins.Get("lc001")?.CurrentKeyPin, Is.EqualTo(lc.Current.ToHex()));

            });

        }

        #endregion

        #region AnImpostorsPin_IsAnsweredWithTheControllersRealPins()

        /// <summary>
        /// A station that learned a pin that is not the controller's - an impostor answered its first handshake
        /// - is handed the controller's real pins all the same, which do not have the learned one: the station
        /// refuses the impostor, and comes back to the real controller.
        /// </summary>
        [Test]
        public async Task AnImpostorsPin_IsAnsweredWithTheControllersRealPins()
        {

            var impostor     = APin();

            lc.PinSetSigner  = ASigningKey();
            lc.Learned       = impostor;

            await KeyPinLearned(impostor);

            await Until(() => !lc.Taken.IsEmpty || !lc.Refused.IsEmpty, "a pin set reaching the station");

            Assert.Multiple(() => {
                Assert.That(lc.Refused,                       Is.Empty, String.Join("; ", lc.Refused));
                Assert.That(lc.Taken.FirstOrDefault().Pins,   Is.EqualTo($"{lc.Current.ToHex()},{lc.Next!.ToHex()}"));
                Assert.That(lc.Taken.FirstOrDefault().Pins,   Does.Not.Contain(impostor.ToHex()), "the impostor's pin was handed out");
                Assert.That(lc.State,                         Is.Not.EqualTo("Confirmed"), "the impostor's pin was confirmed");
            });

        }

        #endregion

        #region AKeyPinLearned_BeforeTheBootNotification_IsConfirmedAllTheSame()

        /// <summary>
        /// A station's KeyPinLearned can come before its BootNotification - a station on probation sends its
        /// queued security events as it connects - which is where the CSMS learns where the station is, and the
        /// OCPP node a route to it: the event itself notes the station behind its controller and routes it
        /// there, and the pin set reaches it.
        /// </summary>
        [Test]
        public async Task AKeyPinLearned_BeforeTheBootNotification_IsConfirmedAllTheSame()
        {

            CSMS.Node.Routing.RemoveStaticRouting(NetworkingNode_Id.Parse(Controller.StationId));
            CSMS.KeyPins.ForgetStation(Controller.StationId);

            Assert.That(CSMS.Node.Routing.LookupNetworkingNode(NetworkingNode_Id.Parse(Controller.StationId), out _), Is.False,
                        "the test's station is still routed, and the test would prove nothing");

            lc.PinSetSigner  = ASigningKey();
            lc.Learned       = lc.Current;

            await KeyPinLearned(lc.Current);

            await Until(() => !lc.Taken.IsEmpty || !lc.Refused.IsEmpty || CSMS.KeyPins.StationOf(Controller.StationId)?.Answer is not null,
                        "a pin set reaching the station, or the CSMS giving up on it");

            Assert.Multiple(() => {
                Assert.That(lc.Taken.Select(taken => taken.Version),             Is.EqualTo(new[] { 4UL }), $"{CSMS.KeyPins.StationOf(Controller.StationId)?.Answer} - {Asked}");
                Assert.That(CSMS.KeyPins.LocalControllerOf(Controller.StationId), Is.EqualTo("lc001"));
            });

        }

        #endregion

        #region WithoutASigningKey_NoPinSetIsSent_AndTheLogSaysHowToMakeOne()

        /// <summary>
        /// A CSMS without a signing key sends no pin set - the station would refuse an unsigned one - and says
        /// how to make the key and confirm the station by hand.
        /// </summary>
        [Test]
        public async Task WithoutASigningKey_NoPinSetIsSent_AndTheLogSaysHowToMakeOne()
        {

            lc.Learned = lc.Current;

            await KeyPinLearned(lc.Current);

            await Until(() => said.Any(line => line.Contains("no signing key for pin sets")), "the log saying why no pin set was sent");

            await Task.Delay(500);

            Assert.Multiple(() => {
                Assert.That(IndexOf(Controller.StationId, "SetVariables"),  Is.EqualTo(-1), $"a pin set was sent: {Asked}");
                Assert.That(said,                                           Has.Some.Contains("keyPins signer create").And.Contains("keyPins confirm cs001"));
            });

        }

        #endregion

        #region TheRollover_HandsTheNextPin_AsksForIt_SwitchesOnlyThen_AndTakesTheOldAway()

        /// <summary>
        /// The rollover in its order: the controller's pins read; the station handed [current, next] with the
        /// version above its own; asked whether it has the next pin; only then the controller switched; and the
        /// station handed [next] with the version above that. The controller stays connected throughout.
        /// </summary>
        [Test]
        public async Task TheRollover_HandsTheNextPin_AsksForIt_SwitchesOnlyThen_AndTakesTheOldAway()
        {

            lc.PinSetSigner  = ASigningKey();
            lc.StationPins   = [ lc.Current ];
            lc.StationVersion = 5;

            var current      = lc.Current;
            var next         = lc.Next!;

            var run          = await CSMS.RolloverAsync("lc001", TimeSpan.Zero);

            var readPins     = IndexOf("lc001",               "GetVariables");
            var both         = IndexOf(Controller.StationId,  "SetVariables", PinsAre(current, next));
            var asked        = IndexOf(Controller.StationId,  "GetVariables");
            var switched     = IndexOf("lc001",               "SetVariables");
            var onlyNext     = IndexOf(Controller.StationId,  "SetVariables", PinsAre(next));

            Assert.Multiple(() => {

                Assert.That(run.Done,                         Is.True, String.Join(Environment.NewLine, run.Said));

                Assert.That(readPins,                         Is.GreaterThanOrEqualTo(0), Asked);
                Assert.That(both,                             Is.GreaterThan(readPins),   $"[current, next] was not handed out after the pins were read: {Asked}");
                Assert.That(asked,                            Is.GreaterThan(both),       $"the station was not asked for its pins after [current, next]: {Asked}");
                Assert.That(switched,                         Is.GreaterThan(asked),      $"the controller was switched before the station was asked: {Asked}");
                Assert.That(onlyNext,                         Is.GreaterThan(switched),   $"[next] was not handed out after the switch: {Asked}");

                Assert.That(lc.Taken.Select(taken => taken.Version), Is.EqualTo(new[] { 6UL, 7UL }));
                Assert.That(lc.StationPins,                   Is.EqualTo(new[] { next }));
                Assert.That(lc.Current,                       Is.EqualTo(next), "the controller was not switched");

                Assert.That(CSMS.IsConnected("lc001"),        Is.True, "the controller lost its connection");
                Assert.That(CSMS.KeyPins.Get("lc001")?.CurrentKeyPin, Is.EqualTo(next.ToHex()), "the store does not say what the controller presents now");
                Assert.That(CSMS.KeyPins.Get("lc001")?.NextKeyPin,    Is.Null);
                Assert.That(CSMS.KeyPins.StationOf(Controller.StationId)?.Version, Is.EqualTo(7));

            });

        }

        #endregion

        #region AStationThatDoesNotTakeTheNextPin_StopsTheRollover_BeforeTheSwitch()

        /// <summary>
        /// A station that refuses [current, next] - it believes no signer - stops the rollover before the
        /// switch, which would lock it out; so does one that took it and reports pins without the next one.
        /// The controller keeps its key, and what is said names the station.
        /// </summary>
        [TestCase(false, Description = "refuses the pin set")]
        [TestCase(true,  Description = "took it, and reports pins without the next one")]
        public async Task AStationThatDoesNotTakeTheNextPin_StopsTheRollover_BeforeTheSwitch(Boolean TookIt)
        {

            var publicKey    = ASigningKey();

            lc.PinSetSigner  = TookIt ? publicKey : null;
            lc.StationPins   = [ lc.Current ];
            lc.LosesTheNextPin = TookIt;

            var current      = lc.Current;

            var run          = await CSMS.RolloverAsync("lc001", TimeSpan.Zero);

            Assert.Multiple(() => {
                Assert.That(run.Done,                         Is.False, "the rollover was done");
                Assert.That(run.Said.LastOrDefault() ?? "",   Does.Contain("cs001").And.Contain("is not switched"));
                Assert.That(IndexOf("lc001", "SetVariables"), Is.EqualTo(-1), $"the controller was told to switch: {Asked}");
                Assert.That(lc.Current,                       Is.EqualTo(current));
            });

        }

        #endregion

        #region WithoutANextKey_TheRolloverIsRefused_AndSaysHowToAnnounceOne()

        /// <summary>
        /// A controller that announced no next key cannot be rolled over: refused, with how to announce one,
        /// and nothing is sent to anybody.
        /// </summary>
        [Test]
        public async Task WithoutANextKey_TheRolloverIsRefused_AndSaysHowToAnnounceOne()
        {

            lc.PinSetSigner  = ASigningKey();
            lc.Next          = null;

            var run          = await CSMS.RolloverAsync("lc001", TimeSpan.Zero);

            Assert.Multiple(() => {
                Assert.That(run.Done,                                              Is.False);
                Assert.That(run.Said.Single(),                                     Does.Contain("serverKeys next"));
                Assert.That(lc.Asked.Select(asked => asked.Action).Distinct(),     Is.EqualTo(new[] { "GetVariables" }), $"more than the pins were asked: {Asked}");
            });

        }

        #endregion

        #region AControllerInStandardMode_OrNotConnected_IsRefused()

        /// <summary>
        /// The stations behind a controller in standard mode cannot be addressed, and one that is not connected
        /// cannot be asked: both are refused before anything is sent, saying why - the first with what to set at
        /// the controller.
        /// </summary>
        [Test]
        public async Task AControllerInStandardMode_OrNotConnected_IsRefused()
        {

            ASigningKey();

            await using var standard  = await AController("lc002", Overlay: false);

            var inStandardMode        = await CSMS.RolloverAsync("lc002", TimeSpan.Zero);
            var notConnected          = await CSMS.RolloverAsync("lc009", TimeSpan.Zero);

            Assert.Multiple(() => {
                Assert.That(CSMS.InOverlayNetwork("lc002"),     Is.False);
                Assert.That(inStandardMode.Done,                Is.False);
                Assert.That(inStandardMode.Said.Single(),       Does.Contain("standard mode").And.Contain("\"networkingMode\": \"overlay\""));
                Assert.That(standard.Asked,                     Is.Empty, "a controller in standard mode was asked something");
                Assert.That(notConnected.Said.Single(),         Does.Contain("not connected"));
            });

        }

        #endregion

        #region TheGracePeriod_KeepsTheOldPin_UntilItIsOver()

        /// <summary>
        /// After the switch the old pin stays for the grace period, and is taken away once it is over.
        /// </summary>
        [Test]
        public async Task TheGracePeriod_KeepsTheOldPin_UntilItIsOver()
        {

            lc.PinSetSigner  = ASigningKey();
            lc.StationPins   = [ lc.Current ];

            var current      = lc.Current;
            var next         = lc.Next!;

            var running      = CSMS.RolloverAsync("lc001", TimeSpan.FromSeconds(3));

            await Until(() => IndexOf("lc001", "SetVariables") >= 0, "the switch");

            await Task.Delay(TimeSpan.FromSeconds(1));

            var duringGrace  = lc.StationPins.ToArray();

            var run          = await running;

            Assert.Multiple(() => {
                Assert.That(duringGrace,      Is.EqualTo(new[] { current, next }), "the old pin was taken away before the grace period was over");
                Assert.That(run.Done,         Is.True, String.Join(Environment.NewLine, run.Said));
                Assert.That(lc.StationPins,   Is.EqualTo(new[] { next }));
            });

        }

        #endregion

        #region ConfirmingAController_PutsRightOnlyTheStationsWhosePinsAreNotItsOwn()

        /// <summary>
        /// keyPins confirm of a whole controller hands its pins to the stations that do not hold exactly them,
        /// and leaves those alone that do.
        /// </summary>
        [Test]
        public async Task ConfirmingAController_PutsRightOnlyTheStationsWhosePinsAreNotItsOwn()
        {

            lc.PinSetSigner   = ASigningKey();
            lc.StationPins    = [ lc.Current, lc.Next! ];

            var held          = await CSMS.ConfirmAsync("lc001");

            lc.StationPins    = [ lc.Current ];

            var putRight      = await CSMS.ConfirmAsync("lc001");

            Assert.Multiple(() => {
                Assert.That(held.Done,                                       Is.True, String.Join(Environment.NewLine, held.Said));
                Assert.That(held.Stations.Single().Answer,                   Is.EqualTo("has them already"));
                Assert.That(putRight.Done,                                   Is.True, String.Join(Environment.NewLine, putRight.Said));
                Assert.That(lc.Taken.Select(taken => taken.Version),         Is.EqualTo(new[] { 4UL }), "not one pin set, for the station that needed it");
                Assert.That(lc.StationPins,                                  Is.EqualTo(new[] { lc.Current, lc.Next! }));
            });

        }

        #endregion


        #region (private) Console() / OverSSHAs(Name, Role) / Run(CLI, CommandLine)

        private CSMSCLI Console()
            => new (CSMS);

        /// <summary>
        /// An account of the given name in the group of the given role, made the way the CSMS makes its first
        /// one, and its password.
        /// </summary>
        private async Task<(IUser Account, String Password)> AnAccount(String  Name,
                                                                       String  Role)
        {

            var password = "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8];

            Assert.That(CSMS.ExtAPI.TryGetOrganization(Organization_Id.Parse(CSMS.DefaultOrganization), out var organization) &&
                        organization is Organization, Is.True, "the CSMS's organization is not there");

            await CSMS.ExtAPI.CreateUser(
                      User_Id.Parse(Name),
                      I18NString.Create(Languages.en, Name),
                      SimpleEMailAddress.Parse($"{Name}@localhost"),
                      User2OrganizationEdgeLabel.IsMember,
                      (Organization) organization!,
                      Password:                  password,
                      SkipDefaultNotifications:  true,
                      SkipNewUserEMail:          true,
                      SkipNewUserNotifications:  true,
                      AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                      IsAuthenticated:           true
                  );

            Assert.That(CSMS.ExtAPI.TryGetUser     (User_Id.     Parse(Name), out var account), Is.True);
            Assert.That(CSMS.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group),   Is.True);

            var joined = await CSMS.ExtAPI.AddUserToUserGroup((User) account!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            Assert.That(joined.IsSuccess, Is.True);

            return (account!, password);

        }

        private async Task<CSMSCLI> OverSSHAs(String  Name,
                                              String  Role)

            => new (CSMS,
                    new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask),
                    new CLICaller((await AnAccount(Name, Role)).Account, null!));

        private static async Task<String> Run(CSMSCLI  CLI,
                                              String   CommandLine)
        {

            var lines = String.Join(Environment.NewLine, await CLI.Execute(CommandLine));

            TestContext.Out.WriteLine($"> {CommandLine}");
            TestContext.Out.WriteLine(lines);

            return lines;

        }

        #endregion

        #region TheCommandLine_MakesTheSigner_ListsAndRollsOver_AndAsksWhoMay()

        /// <summary>
        /// keyPins at the console: the signer made once and shown, the controller and its station listed, a
        /// grace period that is none refused, and the rollover run. Over SSH a cpo may look, and may neither
        /// make the signer nor roll over: those change whom a station believes, the certificates' permission.
        /// </summary>
        [Test]
        public async Task TheCommandLine_MakesTheSigner_ListsAndRollsOver_AndAsksWhoMay()
        {

            using var console  = Console();
            using var cpo      = await OverSSHAs("carla", "cpo");

            var cpoCreate      = await Run(cpo,     "keyPins signer create");
            var created        = await Run(console, "keyPins signer create");
            var again          = await Run(console, "keyPins signer create");
            var shown          = await Run(console, "keyPins signer");

            lc.PinSetSigner    = CSMS.PinSetSigner.PublicKey;
            lc.StationPins     = [ lc.Current ];

            var cpoList        = await Run(cpo,     "keyPins");
            var cpoRollover    = await Run(cpo,     "keyPins rollover lc001 0");
            var badGrace       = await Run(console, "keyPins rollover lc001 soon");
            var rolledOver     = await Run(console, "keyPins rollover lc001 0");
            var listed         = await Run(console, "keyPins show lc001");

            Assert.Multiple(() => {

                Assert.That(cpoCreate,      Does.Contain("'carla' may not do that here"));
                Assert.That(created,        Does.Contain(CSMS.PinSetSigner.PublicKey!));
                Assert.That(again,          Does.Contain("not made anew"));
                Assert.That(shown,          Does.Contain(CSMS.PinSetSigner.PublicKey!));

                Assert.That(cpoList,        Does.Contain("lc001").And.Contain("cs001").And.Contain("overlay"));
                Assert.That(cpoRollover,    Does.Contain("'carla' may not do that here"));
                Assert.That(badGrace,       Does.Contain("no grace period"));
                Assert.That(rolledOver,     Does.Contain("rolled over"));
                Assert.That(listed,         Does.Contain(lc.Current.ToHex()).And.Contain("version 5"));

            });

        }

        #endregion

        #region TheAPI_IsReadAtTheStationsPermission_AndChangedAtTheCertificates()

        /// <summary>
        /// The API: the key pins read by whoever may read the stations; the signer made, a confirmation and a
        /// rollover run only by whoever may edit the certificates - a cpo is refused all three - and the
        /// rollover answered once it is done.
        /// </summary>
        [Test]
        public async Task TheAPI_IsReadAtTheStationsPermission_AndChangedAtTheCertificates()
        {

            var (_, cpoPassword) = await AnAccount("carla", "cpo");

            var admin            = await SignedIn();
            var cpo              = await SignedInAs("carla", cpoPassword);

            var cpoSigner        = await cpo.  PostAsync("/api/v1/key-pins/signer", null);
            var made             = await admin.PostAsync("/api/v1/key-pins/signer", null);
            var madeAgain        = await admin.PostAsync("/api/v1/key-pins/signer", null);

            lc.PinSetSigner      = CSMS.PinSetSigner.PublicKey;
            lc.StationPins       = [ lc.Current ];

            var cpoRead          = await cpo.  GetAsync ("/api/v1/key-pins");
            var cpoConfirm       = await cpo.  PostAsync("/api/v1/key-pins/confirm/cs001",                           null);
            var cpoRollover      = await cpo.  PostAsync("/api/v1/key-pins/local-controllers/lc001/rollover",       JSONBody(new JProperty("graceSeconds", 0)));
            var badGrace         = await admin.PostAsync("/api/v1/key-pins/local-controllers/lc001/rollover",       JSONBody(new JProperty("graceSeconds", -1)));
            var rollover         = await admin.PostAsync("/api/v1/key-pins/local-controllers/lc001/rollover",       JSONBody(new JProperty("graceSeconds", 0)));
            var unknown          = await admin.GetAsync ("/api/v1/key-pins/local-controllers/lc404");
            var one              = await GetJSON(admin, "/api/v1/key-pins/local-controllers/lc001");

            var rolled           = JObject.Parse(await rollover.Content.ReadAsStringAsync());

            Assert.Multiple(() => {

                Assert.That(cpoSigner.StatusCode,                         Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(made.StatusCode,                              Is.EqualTo(HttpStatusCode.Created));
                Assert.That(madeAgain.StatusCode,                         Is.EqualTo(HttpStatusCode.Conflict));

                Assert.That(cpoRead.StatusCode,                           Is.EqualTo(HttpStatusCode.OK));
                Assert.That(cpoConfirm.StatusCode,                        Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(cpoRollover.StatusCode,                       Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(badGrace.StatusCode,                          Is.EqualTo(HttpStatusCode.BadRequest));

                Assert.That(rollover.StatusCode,                          Is.EqualTo(HttpStatusCode.OK), rolled.ToString());
                Assert.That(rolled["done"]?.Value<Boolean>(),             Is.True);
                Assert.That(unknown.StatusCode,                           Is.EqualTo(HttpStatusCode.NotFound));

                Assert.That(one["currentKeyPin"]?.Value<String>(),        Is.EqualTo(lc.Current.ToHex()));
                Assert.That(one["inOverlayNetwork"]?.Value<Boolean>(),    Is.True);
                Assert.That(one["stations"]?[0]?["station"]?.Value<String>(), Is.EqualTo("cs001"));

            });

        }

        #endregion


        #region (private) NamedBy(Node, Action)

        /// <summary>
        /// Whom the requests of the given action that reached the given node named as where they come from,
        /// once there is one or the patience has run out.
        /// </summary>
        private static async Task<String[]> NamedBy(Controller  Node,
                                                    String      Action)
        {

            var giveUp = DateTimeOffset.UtcNow + Patience;

            while (!Node.AskedBy.Any(asked => asked.Action == Action) && DateTimeOffset.UtcNow < giveUp)
                await Task.Delay(20);

            return [.. Node.AskedBy.Where(asked => asked.Action == Action).Select(asked => asked.From)];

        }

        #endregion

        #region AStationsNextSSHKey_IsInstalledAtItsController_InTheCSMSsName()

        /// <summary>
        /// A station behind the controller asks with SignSSHKey for its next key: the CSMS lists the keys at
        /// the controller and installs the next one there - with requests that name the CSMS as where they
        /// come from, as the overlay network wants it. Ones that name nobody are answered to nobody.
        /// </summary>
        [Test]
        public async Task AStationsNextSSHKey_IsInstalledAtItsController_InTheCSMSsName()
        {

            var key     = org.GraphDefined.Vanaheimr.Hermod.SSH.SshHostKey.GenerateEd25519();
            var line    = org.GraphDefined.Vanaheimr.Hermod.SSH.SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine();

            var asked   = await lc.AsStation("SignSSHKey", new JObject(new JProperty("purpose",    "OCPP"),
                                                                        new JProperty("publicKey",  line)));

            var listed  = await NamedBy(lc, "GetInstalledSSHKeys");
            var install = await NamedBy(lc, "InstallSSHKey");
            var signed  = await NamedBy(lc, "SSHKeySigned");
            var deleted = await NamedBy(lc, "DeleteSSHKey");
            var csms    = CSMS.Node.Id.ToString();

            Assert.Multiple(() => {
                Assert.That(asked[4]?["status"]?.Value<String>(),  Is.EqualTo("Accepted"), asked.ToString(Formatting.None));
                Assert.That(listed,                                 Is.EqualTo(new[] { csms }), $"GetInstalledSSHKeys: {Asked}");
                Assert.That(install,                                Is.EqualTo(new[] { csms }), $"InstallSSHKey: {Asked}");
                Assert.That(signed,                                 Is.EqualTo(new[] { csms }), $"SSHKeySigned: {Asked}");
                Assert.That(deleted,                                Is.EqualTo(new[] { csms }), $"DeleteSSHKey of the old key: {Asked}");
            });

        }

        #endregion

        #region AStationsNextSSHKey_IsSignedHere_InTheCSMSsName()

        /// <summary>
        /// A station connected to the CSMS itself in the overlay network asks with SignSSHKey for its next key:
        /// the CSMS takes it beside the current one and tells the station with SSHKeySigned - naming itself as
        /// where that comes from.
        /// </summary>
        [Test]
        public async Task AStationsNextSSHKey_IsSignedHere_InTheCSMSsName()
        {

            await using var station = await AController("cs007", Overlay: true);

            var key     = org.GraphDefined.Vanaheimr.Hermod.SSH.SshHostKey.GenerateEd25519();
            var line    = org.GraphDefined.Vanaheimr.Hermod.SSH.SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine();

            var asked   = await station.AsController("SignSSHKey", new JObject(new JProperty("purpose",    "OCPP"),
                                                                              new JProperty("publicKey",  line)));

            var signed  = await NamedBy(station, "SSHKeySigned");

            Assert.Multiple(() => {
                Assert.That(asked[4]?["status"]?.Value<String>(),  Is.EqualTo("Accepted"), asked.ToString(Formatting.None));
                Assert.That(signed,                                 Is.EqualTo(new[] { CSMS.Node.Id.ToString() }), "SSHKeySigned");
            });

        }

        #endregion

        #region TheRootsOfAStation_AreAskedFor_InTheCSMSsName()

        /// <summary>
        /// A station connected to the CSMS itself in the overlay network is asked for its certificates, given a
        /// root and told to delete one - each request naming the CSMS as where it comes from.
        /// </summary>
        [Test]
        public async Task TheRootsOfAStation_AreAskedFor_InTheCSMSsName()
        {

            await using var station = await AController("cs007", Overlay: true);

            using var rootKey  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var root     = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256).
                                     CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            var stationRoot    = new cloud.charging.open.CSMS.OCPP.StationRoot("test-root",
                                                                               "CSMSRootCertificate",
                                                                               root.ExportCertificatePem(),
                                                                               root.Subject,
                                                                               root.SerialNumber,
                                                                               root.NotAfter,
                                                                               DateTimeOffset.UtcNow,
                                                                               false);

            await CSMS.InstalledOn("cs007");
            await CSMS.InstallRoot("cs007", stationRoot);
            await CSMS.DeleteFrom ("cs007", "CSMSRootCertificate", "SHA256", "00", "00", root.SerialNumber);

            var csms       = CSMS.Node.Id.ToString();

            var listed     = await NamedBy(station, "GetInstalledCertificateIds");
            var installed  = await NamedBy(station, "InstallCertificate");
            var deleted    = await NamedBy(station, "DeleteCertificate");

            Assert.Multiple(() => {
                Assert.That(listed,     Is.EqualTo(new[] { csms }), "GetInstalledCertificateIds");
                Assert.That(installed,  Is.EqualTo(new[] { csms }), "InstallCertificate");
                Assert.That(deleted,    Is.EqualTo(new[] { csms }), "DeleteCertificate");
            });

        }

        #endregion

    }

}
