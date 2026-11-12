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
using System.Globalization;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.WebSockets;

using OCPPv2_1      = cloud.charging.open.protocols.OCPPv2_1;
using OCPPv2_1_CS   = cloud.charging.open.protocols.OCPPv2_1.CS;
using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;
using OCPPResultCode = cloud.charging.open.protocols.OCPP.ResultCode;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// What came of handing one charging station a pin set.
    /// </summary>
    /// <param name="Station">The charging station.</param>
    /// <param name="Connection">The instance of TLSClientController the pins are for: its endpoint to its Local Controller; null where none was found.</param>
    /// <param name="Version">The version of the pin set - or of the one it holds, where it had the pins already.</param>
    /// <param name="Pins">The key pins of the pin set, in hexadecimal.</param>
    /// <param name="Accepted">Whether the station has them now.</param>
    /// <param name="Answer">What it answered, or why it could not be asked, in a few words.</param>
    public sealed record PinSetOutcome(String                 Station,
                                       String?                Connection,
                                       UInt64?                Version,
                                       IReadOnlyList<String>  Pins,
                                       Boolean                Accepted,
                                       String                 Answer)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("station",     Station),
                   new JProperty("connection",  Connection),
                   new JProperty("version",     Version),
                   new JProperty("pins",        new JArray(Pins)),
                   new JProperty("accepted",    Accepted),
                   new JProperty("answer",      Answer)
               );

    }


    /// <summary>
    /// What came of a confirmation or a rollover: whether it was done, what was said on the way, and what each
    /// station answered.
    /// </summary>
    public sealed record KeyPinRun(Boolean                       Done,
                                   IReadOnlyList<String>         Said,
                                   IReadOnlyList<PinSetOutcome>  Stations)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("done",      Done),
                   new JProperty("said",      new JArray(Said)),
                   new JProperty("stations",  new JArray(Stations.Select(station => station.ToJSON())))
               );

    }


    /// <summary>
    /// The keys of a Local Controller's station port, as it reported them: EVQICtrlr[TLSServer].
    /// </summary>
    /// <param name="Current">The key pin of the key it presents now.</param>
    /// <param name="Next">The key pin of the next key it announced; null for none.</param>
    /// <param name="KeyCreated">When the current key was made.</param>
    /// <param name="Problem">Why they could not be read; null where they were.</param>
    public sealed record LocalControllerKeys(KeyPin?          Current,
                                             KeyPin?          Next,
                                             DateTimeOffset?  KeyCreated,
                                             String?          Problem);


    /// <summary>
    /// An endpoint of a charging station over TLS, as its report of TLSClientController says it.
    /// </summary>
    /// <param name="Connection">The instance: the station's connection id.</param>
    /// <param name="URL">Where it dials.</param>
    /// <param name="ServerKeyPins">The key pins it holds.</param>
    /// <param name="Version">The version of the pin set they came from.</param>
    /// <param name="State">Configured, Learned or Confirmed.</param>
    /// <param name="Learned">The key pin learned on first use, while it is on probation.</param>
    /// <param name="Shown">The key pin of the key its server presented at the last handshake.</param>
    public sealed record StationEndpoint(String                 Connection,
                                         String?                URL,
                                         IReadOnlyList<KeyPin>  ServerKeyPins,
                                         UInt64                 Version,
                                         String?                State,
                                         KeyPin?                Learned,
                                         KeyPin?                Shown);


    /// <summary>
    /// The key pins of the charging stations behind this CSMS's Local Controllers (white paper "Key Pins and
    /// TLS 1.3 Raw Public Keys for Local Controllers", sections 5.5 to 5.7, work package K4, phase B3): a pin
    /// learned on first use confirmed by a signed pin set, and a Local Controller's server key rolled over
    /// without a station losing its connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Which stations are behind which controller</b> is learned from their BootNotifications, whose network
    /// path names the controller as its last hop where the controller dials this CSMS in the overlay network -
    /// and kept in <see cref="KeyPinStore"/>, beside the configuration file, from which the routes to them are
    /// put back at the next start. The first controller a station comes through keeps it: a frame that names
    /// another node as its way moves nothing, as any node in the overlay network can name itself the way to
    /// any station. A station that did move is forgotten by hand - 'keyPins forget' - and noted anew.
    /// </para>
    /// <para>
    /// <b>A pin set</b> is one SetVariables of a station's TLSClientController[&lt;connection&gt;]: ServerKeyPins and a
    /// higher ServerKeyPinsVersion, signed by <see cref="PinSetSigner"/>, whose public key the station holds as
    /// one of its pin set signers. The instance is the endpoint whose learned or shown key pin, or whose pins,
    /// are the controller's - read from the station's report of TLSClientController before every pin set,
    /// which gives the version it holds as well.
    /// </para>
    /// <para>
    /// <b>Confirmation</b> (sections 5.6 and 5.7): a station behind a controller that reports KeyPinLearned is
    /// handed the controller's real pins, as the controller reports them - its current key's, and the next
    /// key's where one is announced. Whether the pin it learned is among them or not: it is confirmed, or the
    /// station refuses the server it learned it of and comes back to the real one.
    /// </para>
    /// <para>
    /// <b>Rollover</b> (section 5.5): every station behind the controller is handed [current, next], each is
    /// asked whether it has the next pin, and only then is the controller told to switch; after a grace period
    /// the old pin is taken away. A station that does not have the next pin stops the rollover before the
    /// switch, as it could not connect again after it.
    /// </para>
    /// <para>
    /// One run at a time per controller: a confirmation that comes in during a rollover waits for it, as both
    /// raise the versions the same stations hold.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// How long a rollover waits between the switch and taking the old key pin away, unless it is told
        /// otherwise.
        /// </summary>
        /// <remarks>
        /// Short: a station connected before the switch stays connected, and one that dials after it is shown
        /// the next key, which it has. The old pin is left for what is under way at the moment of the switch -
        /// a station dialling just then.
        /// </remarks>
        public static readonly TimeSpan  DefaultRolloverGrace  = TimeSpan.FromSeconds(30);

        /// <summary>
        /// The longest grace period a rollover may be given.
        /// </summary>
        public static readonly TimeSpan  MaxRolloverGrace      = TimeSpan.FromDays(1);

        /// <summary>
        /// The component, instance and variables of a Local Controller's station port keys.
        /// </summary>
        public const  String  EVQICtrlr              = "EVQICtrlr";
        public const  String  TLSServer              = "TLSServer";

        /// <summary>
        /// The component of a charging station's TLS endpoints.
        /// </summary>
        public const  String  TLSClientController    = "TLSClientController";

        /// <summary>
        /// The security events of the white paper's section 7.5 a station reports.
        /// </summary>
        public const  String  KeyPinLearned          = "KeyPinLearned";
        public const  String  KeyPinConfirmed        = "KeyPinConfirmed";
        public const  String  KeyPinRejected         = "KeyPinRejected";
        public const  String  KeyPinProbationExpired = "KeyPinProbationExpired";

        /// <summary>
        /// What a Local Controller's techInfo of ReconfigurationOfSecurityParameters begins with after it switched
        /// its station port's key.
        /// </summary>
        public const  String  ServerKeySwitched      = "TLS server key switched";

        /// <summary>
        /// The endpoint a station's techInfo of KeyPinLearned names: "... of endpoint '&lt;id&gt;' ...".
        /// </summary>
        private static readonly Regex  endpointNamed  = new ("endpoint '([^']+)'", RegexOptions.CultureInvariant);

        private readonly ConcurrentDictionary<String, SemaphoreSlim>                            keyPinRuns  = new (StringComparer.Ordinal);
        private readonly ConcurrentDictionary<(String Station, Int32 RequestId), ReportCollector>  reports     = new ();

        #endregion

        #region Properties

        /// <summary>
        /// The key this CSMS signs pin sets with.
        /// </summary>
        public PinSetSigningKey  PinSetSigner    { get; private set; } = new ();

        /// <summary>
        /// The Local Controllers, the stations behind them and the pin sets they were handed.
        /// </summary>
        public KeyPinStore       KeyPins         { get; private set; } = new ();

        /// <summary>
        /// How long a station's report of TLSClientController is waited for after it accepted GetReport.
        /// </summary>
        public TimeSpan          KeyPinReportPatience    { get; set; } = TimeSpan.FromSeconds(30);

        #endregion


        #region (private) BuildKeyPins()

        /// <summary>
        /// The signing key and the store, read from beside the configuration file; the routes to the stations
        /// behind the controllers put back; and what the OCPP node is told that concerns them.
        /// </summary>
        private void BuildKeyPins()
        {

            var directory = Path.GetDirectoryName(ConfigFile.Path) ?? ".";

            PinSetSigner = new PinSetSigningKey(Path.Combine(directory, PinSetSigningKey.DefaultFileName), TimeProvider);
            PinSetSigner.OnNotice += (level, message) => Log.Log(level, message, "ocpp", "keypins", "security");

            // A key that is there and cannot be read is said, and not made
            // anew: the stations believe that one.
            if (!PinSetSigner.TryLoad(out var signerError))
                Log.Error($"The signing key for pin sets could not be read: {signerError} No pin set is signed until it is repaired.",
                          "ocpp", "keypins", "security");

            KeyPins = new KeyPinStore(Path.Combine(directory, KeyPinStore.DefaultFileName));
            KeyPins.OnNotice += (level, message) => Log.Log(level, message, "ocpp", "keypins");
            KeyPins.Load();

            // The routes the OCPP node learns from BootNotifications are gone
            // with a restart, and a station behind a controller does not boot
            // again because this CSMS did.
            foreach (var controller in KeyPins.All)
                foreach (var station in controller.Stations ?? [])
                    RouteThrough(station.Station, controller.LocalController);

            csms01.OCPP.OUT.OnBootNotificationResponseSent += (timestamp, sender, connection, request, response, runtime, sentMessageResult, cancellationToken) => {
                NoteWhereAStationIs(request.NetworkPath);
                return Task.CompletedTask;
            };

            // Routed as it comes in, before it is answered: a KeyPinLearned can
            // come before the station's BootNotification, which is where the
            // node learns a route to it - and the answer goes by that route.
            csms01.OCPP.IN.OnSecurityEventNotificationRequestReceived += (timestamp, sender, connection, request, cancellationToken) => {
                RouteAStationThatLearned(request);
                return Task.CompletedTask;
            };

            csms01.OCPP.OUT.OnSecurityEventNotificationResponseSent += (timestamp, sender, connection, request, response, runtime, sentMessageResult, cancellationToken) => {
                OnKeyPinSecurityEvent(request);
                return Task.CompletedTask;
            };

            csms01.OCPP.IN.OnNotifyReportRequestReceived += (timestamp, sender, connection, request, cancellationToken) => {
                CollectReport(request);
                return Task.CompletedTask;
            };

        }

        #endregion

        #region (private) NoteWhereAStationIs(NetworkPath)

        /// <summary>
        /// A BootNotification's network path: a station behind a Local Controller where the controller is its
        /// last hop, and one that came straight here otherwise.
        /// </summary>
        private void NoteWhereAStationIs(NetworkPath Path)
        {

            try
            {

                var station = Path.Source.ToString();

                if (Path.Length > 1 && Path.Last != Path.Source)
                    NoteBehind(station, Path.Last.ToString());

                else if (KeyPins.ForgetStation(station))
                    Log.Info($"The charging station '{station}' came straight to this CSMS: it is behind no local controller any more.",
                             "ocpp", "keypins", "station");

            }
            catch (Exception e)
            {
                Log.Exception(e, "Where a charging station is could not be noted.", "ocpp", "keypins");
            }

        }

        #endregion

        #region (private) NoteBehind(Station, LocalController) / RouteThrough(Station, LocalController, Formerly)

        /// <summary>
        /// A station is behind the given Local Controller: noted, and routed through it - unless it is noted
        /// behind another one already, where it is left.
        /// </summary>
        /// <remarks>
        /// Not moved by what a frame says: any node that dials this CSMS in the overlay network - a charging
        /// station as well as a controller - can name itself the last hop of any station, and a station moved
        /// by that would have its requests, and the pin sets signed of that node's key pins, go wherever that
        /// node wants. A station that did move is forgotten by hand (<see cref="ForgetWhereAStationIs"/>), and
        /// noted anew by its next BootNotification.
        /// </remarks>
        private void NoteBehind(String  Station,
                                String  LocalController)
        {

            if (KeyPins.LocalControllerOf(Station) is String noted && noted != LocalController)
            {
                Log.Warning($"'{LocalController}' names itself the way to the charging station '{Station}', which is behind '{noted}': the station " +
                            $"is left there, and nothing for it goes to '{LocalController}'. If it did move, 'keyPins forget {Station}' lets its " +
                             "next BootNotification note it behind the local controller it comes through.",
                            "ocpp", "keypins", "security");
                return;
            }

            if (KeyPins.NoteStation(Station, LocalController, TimeProvider.GetUtcNow()))
                Log.Info($"The charging station '{Station}' is behind the local controller '{LocalController}': its pin sets go through it.",
                         "ocpp", "keypins", "station");

            RouteThrough(Station, LocalController);

        }

        /// <summary>
        /// Route the station through the given Local Controller, where the OCPP node has no route to it: a
        /// station's KeyPinLearned can come before its BootNotification, which is where the node learns one.
        /// </summary>
        private void RouteThrough(String  Station,
                                  String  LocalController)
        {

            if (!NetworkingNode_Id.TryParse(Station,         out var station) ||
                !NetworkingNode_Id.TryParse(LocalController, out var controller))
            {
                return;
            }

            if (!csms01.Routing.LookupNetworkingNode(station, out _))
                csms01.Routing.AddOrUpdateStaticRouting(station, controller);

        }

        #endregion

        #region ForgetWhereAStationIs(Station)

        /// <summary>
        /// Forget the Local Controller a charging station is behind, and the route to it through that
        /// controller: for a station that did move, which its next BootNotification - through the controller
        /// it is behind now - notes there.
        /// </summary>
        /// <returns>The controller it was behind; null where it was known behind none.</returns>
        public String? ForgetWhereAStationIs(String Station)
        {

            var station     = Station.Trim();
            var controller  = KeyPins.LocalControllerOf(station);

            if (controller is null)
                return null;

            KeyPins.ForgetStation(station);

            if (NetworkingNode_Id.TryParse(station,    out var id) &&
                NetworkingNode_Id.TryParse(controller, out var through))
            {
                csms01.Routing.RemoveStaticRouting(id, through);
            }

            return controller;

        }

        #endregion

        #region (private) RouteAStationThatLearned(Request)

        /// <summary>
        /// A KeyPinLearned of a station behind a Local Controller, as it comes in: the station noted behind its
        /// controller and routed through it, so that the answer reaches it, and the pin set after it.
        /// </summary>
        private void RouteAStationThatLearned(OCPPv2_1_CS.SecurityEventNotificationRequest Request)
        {

            try
            {

                var path = Request.NetworkPath;

                if (Request.Type.ToString() == KeyPinLearned && path.Length > 1 && path.Last != path.Source)
                    NoteBehind(path.Source.ToString(), path.Last.ToString());

            }
            catch (Exception e)
            {
                Log.Exception(e, "A charging station that learned a key pin could not be routed.", "ocpp", "keypins");
            }

        }

        #endregion

        #region (private) OnKeyPinSecurityEvent(Request)

        /// <summary>
        /// The security events of key pins: a station behind a Local Controller that learned its pin on first
        /// use is handed the controller's real pins; one that was confirmed or rejected, or whose probation
        /// ran out, is said; a controller that switched its key is read again.
        /// </summary>
        private void OnKeyPinSecurityEvent(OCPPv2_1_CS.SecurityEventNotificationRequest Request)
        {

            var type        = Request.Type.ToString();
            var path        = Request.NetworkPath;
            var techInfo    = Request.TechInfo ?? "";

            String source;

            try
            {
                source = path.Source.ToString();
            }
            catch
            {
                return;
            }

            var controller  = path.Length > 1 && path.Last != path.Source
                                  ? path.Last.ToString()
                                  : null;

            switch (type)
            {

                // Sent up by a node that is not the station's controller: that
                // node's pins would be read as the controller's, signed, and
                // handed to that node.
                case KeyPinLearned when controller is not null &&
                                        KeyPins.LocalControllerOf(source) is String noted &&
                                        noted != controller:

                    Log.Warning($"The charging station '{source}' learned a key pin on first use, the event says through '{controller}' - but it is " +
                                $"behind '{noted}': no pin set is sent for it. {techInfo}",
                                "ocpp", "keypins", "security");
                    break;

                case KeyPinLearned when controller is not null:

                    Log.Notice($"The charging station '{source}' behind '{controller}' learned the key pin of its endpoint to it on first use, " +
                               $"and waits for a signed pin set: {techInfo}",
                               "ocpp", "keypins", "security");

                    var named = endpointNamed.Match(techInfo) is { Success: true } match ? match.Groups[1].Value : null;

                    _ = Task.Run(() => ConfirmLearnedKeyPin(source, controller, named));
                    break;

                case KeyPinLearned:
                    Log.Info($"The charging station '{source}' learned a key pin on first use, and is behind no local controller this CSMS knows of: " +
                             $"this CSMS confirms the pins of local controllers only. {techInfo}",
                             "ocpp", "keypins", "security");
                    break;

                case KeyPinConfirmed:
                    Log.Notice ($"The charging station '{source}' confirmed the key pin it learned: {techInfo}", "ocpp", "keypins", "security");
                    break;

                case KeyPinRejected:
                    Log.Warning($"The charging station '{source}' refused the server it learned a key pin of - it is not the local controller " +
                                $"this CSMS knows - and is held to the signed pins: {techInfo}", "ocpp", "keypins", "security");
                    break;

                case KeyPinProbationExpired:
                    Log.Warning($"The charging station '{source}' got no signed pin set in time and forgot the key pin it learned: {techInfo}",
                                "ocpp", "keypins", "security");
                    break;

                case "ReconfigurationOfSecurityParameters" when controller is null && techInfo.StartsWith(ServerKeySwitched, StringComparison.Ordinal):

                    Log.Notice($"The local controller '{source}' switched the key of its station port: {techInfo}", "ocpp", "keypins", "security");

                    // Read again, so that what is shown is what it presents.
                    _ = Task.Run(() => ReadLocalControllerKeysAsync(source));
                    break;

            }

        }

        #endregion

        #region (private) ConfirmLearnedKeyPin(Station, LocalController, Named)

        /// <summary>
        /// Hand a station that learned its controller's key pin on first use the controller's real pins - where
        /// this CSMS has a key to sign them with.
        /// </summary>
        private async Task ConfirmLearnedKeyPin(String   Station,
                                                String   LocalController,
                                                String?  Named)
        {

            try
            {

                if (!PinSetSigner.Exists)
                {
                    Log.Warning($"The charging station '{Station}' behind '{LocalController}' is not sent a pin set to confirm the key pin it learned: " +
                                "this CSMS has no signing key for pin sets. Make one with 'keyPins signer create', give its public key to the station " +
                                $"as a pin set signer, and confirm with 'keyPins confirm {Station}' before its probation runs out.",
                                "ocpp", "keypins", "security");
                    return;
                }

                var run = await ConfirmAsync(Station, Named);

                foreach (var line in run.Said)
                    Log.Log(run.Done ? LogLevel.Info : LogLevel.Warning, line, "ocpp", "keypins", "security");

            }
            catch (Exception e)
            {
                Log.Exception(e, $"The key pin '{Station}' learned could not be confirmed.", "ocpp", "keypins", "security");
            }

        }

        #endregion


        #region InOverlayNetwork(Node)

        /// <summary>
        /// Whether the given node dialled this CSMS in the overlay network - X-OCPP-NetworkingMode said so - which
        /// is what lets this CSMS address the stations behind it.
        /// </summary>
        public Boolean InOverlayNetwork(String Node)

            => ocppWebSocketServer?.WebSocketConnections.Any(connection => StationOn(connection) == Node &&
                                                                           connection.TryGetCustomDataAs<NetworkingMode>(WebSocketKeys.NetworkingMode, out var mode) &&
                                                                           mode == NetworkingMode.OverlayNetwork) ?? false;

        #endregion

        #region ReadLocalControllerKeysAsync(LocalController)

        /// <summary>
        /// Read the keys of a Local Controller's station port - EVQICtrlr[TLSServer] - and note them.
        /// </summary>
        public async Task<LocalControllerKeys> ReadLocalControllerKeysAsync(String LocalController)
        {

            if (!NetworkingNode_Id.TryParse(LocalController, out var id))
                return new LocalControllerKeys(null, null, null, $"'{LocalController}' is no identity of a networking node.");

            try
            {

                var response = await csms01.OCPP.OUT.GetVariables(
                                         new OCPPv2_1_CSMS.GetVariablesRequest(
                                             SourceRouting.To(id),
                                             [.. new[] { "ActiveKeyPin", "NextKeyPin", "KeyCreated" }.
                                                     Select(variable => new OCPPv2_1.GetVariableData(new OCPPv2_1.Component(EVQICtrlr, TLSServer),
                                                                                                     new OCPPv2_1.Variable(variable)))],
                                             NetworkPath: FromThisCSMS
                                         )
                                     );

                if (response.Result.ResultCode != OCPPResultCode.OK)
                    return new LocalControllerKeys(null, null, null,
                                                   $"'{LocalController}' did not answer GetVariables of {EVQICtrlr}[{TLSServer}]: " +
                                                   $"{WhyNot(response.Result)}");

                var results = response.Results.
                                  Where (result => result.Component.Name == EVQICtrlr).
                                  GroupBy(result => result.Variable.Name).
                                  ToDictionary(group => group.Key, group => group.First());

                if (!results.TryGetValue("ActiveKeyPin", out var active) || active.AttributeStatus != OCPPv2_1.GetVariableStatus.Accepted)
                    return new LocalControllerKeys(null, null, null,
                                                   $"'{LocalController}' has no {EVQICtrlr}[{TLSServer}].ActiveKeyPin ({active?.AttributeStatus.ToString() ?? "no answer"}): " +
                                                   "it is no local controller with keys of its station port, or it has none yet.");

                if (!KeyPin.TryParse(active.AttributeValue, out var current))
                    return new LocalControllerKeys(null, null, null,
                                                   $"'{LocalController}' answered '{active.AttributeValue}' for its current key pin, which is no key pin.");

                KeyPin? next = null;

                if (results.TryGetValue("NextKeyPin", out var nextResult) &&
                    nextResult.AttributeStatus == OCPPv2_1.GetVariableStatus.Accepted &&
                    !String.IsNullOrWhiteSpace(nextResult.AttributeValue) &&
                    !KeyPin.TryParse(nextResult.AttributeValue, out next))
                {
                    return new LocalControllerKeys(current, null, null,
                                                   $"'{LocalController}' answered '{nextResult.AttributeValue}' for its next key pin, which is no key pin.");
                }

                DateTimeOffset? created = results.TryGetValue("KeyCreated", out var createdResult) &&
                                          DateTimeOffset.TryParse(createdResult.AttributeValue, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at)
                                              ? at
                                              : null;

                KeyPins.NotePins(LocalController, current.ToHex(), next?.ToHex(), created, TimeProvider.GetUtcNow());

                return new LocalControllerKeys(current, next, created, null);

            }
            catch (Exception e)
            {
                return new LocalControllerKeys(null, null, null, $"The keys of '{LocalController}' could not be read: {e.Message}");
            }

        }

        #endregion

        #region ConfirmAsync(StationOrLocalController, Named = null, CancellationToken = default)

        /// <summary>
        /// Hand a charging station behind a Local Controller - or every one behind the given controller - the
        /// controller's key pins as it reports them now: its current key's, and the next key's where one is
        /// announced, with a version above the one the station holds.
        /// </summary>
        /// <remarks>
        /// What confirms a pin learned on first use, or refuses it where it is not the controller's; and what
        /// puts right a station whose pins are not the controller's any more - a switch made at the controller,
        /// or a rollover cut off before it took the old pin away. A station of a whole controller that holds
        /// exactly those pins already, and is not on probation, is left alone.
        /// </remarks>
        /// <param name="StationOrLocalController">A charging station known behind a Local Controller, or a Local Controller.</param>
        /// <param name="Named">The endpoint the station named in its KeyPinLearned, where it did.</param>
        /// <param name="CancellationToken">To stop between stations.</param>
        public async Task<KeyPinRun> ConfirmAsync(String             StationOrLocalController,
                                                  String?            Named               = null,
                                                  CancellationToken  CancellationToken   = default)
        {

            var target      = StationOrLocalController.Trim();
            var whole       = KeyPins.Get(target) is not null;
            var controller  = whole ? target : KeyPins.LocalControllerOf(target);

            if (controller is null)
                return Refused($"'{target}' is neither a local controller nor a charging station known behind one. A station is known behind its local " +
                                "controller once its BootNotification came through it, with the controller dialling this CSMS in the overlay network.");

            if (WhyNotNow(controller) is String why)
                return Refused(why);

            var runLock = keyPinRuns.GetOrAdd(controller, _ => new SemaphoreSlim(1, 1));

            await runLock.WaitAsync(CancellationToken);

            try
            {

                var said   = new List<String>();
                var keys   = await ReadLocalControllerKeysAsync(controller);

                if (keys.Problem is not null || keys.Current is null)
                    return Refused(keys.Problem ?? $"'{controller}' reported no current key pin.");

                var pins   = new[] { keys.Current, keys.Next }.OfType<KeyPin>().ToArray();

                said.Add($"'{controller}' presents the key pin {keys.Current}" +
                         (keys.Next is not null ? $" and announced the next key pin {keys.Next}." : "."));

                String[] stations  = whole
                                         ? [.. (KeyPins.Get(controller)?.Stations ?? []).Select(station => station.Station)]
                                         : [ target ];

                if (stations.Length == 0)
                    said.Add($"No charging station is known behind '{controller}'.");

                var outcomes   = new List<PinSetOutcome>();

                foreach (var station in stations)
                {

                    CancellationToken.ThrowIfCancellationRequested();

                    var outcome = await HandOver(station, controller, pins, pins, whole ? null : Named, LeaveWhereHeld: whole);

                    outcomes.Add(outcome);
                    said.Add(Said(outcome));

                }

                return new KeyPinRun(outcomes.All(outcome => outcome.Accepted), said, outcomes);

            }
            finally
            {
                runLock.Release();
            }

        }

        #endregion

        #region RolloverAsync(LocalController, Grace = null, CancellationToken = default)

        /// <summary>
        /// Roll a Local Controller's station port over to its announced next key, without a station behind it
        /// losing its connection (white paper, section 5.5): every station is handed [current, next], each is
        /// asked whether it has the next pin, the controller is told to switch only then, and after the grace
        /// period every station is handed [next].
        /// </summary>
        /// <param name="LocalController">The Local Controller, by its identity at this CSMS.</param>
        /// <param name="Grace">How long the old pin is left after the switch; <see cref="DefaultRolloverGrace"/> by default, zero for at once.</param>
        /// <param name="CancellationToken">To stop: before the switch nothing is switched, during the grace the old pin stays until 'keyPins confirm' takes it away.</param>
        public async Task<KeyPinRun> RolloverAsync(String             LocalController,
                                                   TimeSpan?          Grace               = null,
                                                   CancellationToken  CancellationToken   = default)
        {

            var controller  = LocalController.Trim();
            var grace       = Grace ?? DefaultRolloverGrace;

            if (grace < TimeSpan.Zero || grace > MaxRolloverGrace)
                return Refused($"A grace period of {grace} is none this CSMS waits: from zero to {MaxRolloverGrace.TotalHours:0} hours.");

            if (WhyNotNow(controller) is String why)
                return Refused(why);

            var runLock = keyPinRuns.GetOrAdd(controller, _ => new SemaphoreSlim(1, 1));

            await runLock.WaitAsync(CancellationToken);

            try
            {

                var said      = new List<String>();
                var outcomes  = new List<PinSetOutcome>();

                #region 1. The controller's keys: a next one has to be announced

                var keys = await ReadLocalControllerKeysAsync(controller);

                if (keys.Problem is not null || keys.Current is null)
                    return Refused(keys.Problem ?? $"'{controller}' reported no current key pin.");

                if (keys.Next is null)
                    return Refused($"'{controller}' has announced no next key: its station port has the key pin {keys.Current} alone. Announce one at the " +
                                    "local controller - 'serverKeys next' on its command line, or on its server keys page - and roll over again.");

                var current   = keys.Current;
                var next      = keys.Next;

                said.Add($"'{controller}' presents the key pin {current} and announced the next key pin {next}.");

                var stations  = (KeyPins.Get(controller)?.Stations ?? []).Select(station => station.Station).ToArray();

                said.Add(stations.Length > 0
                             ? $"{stations.Length} charging station(s) are known behind '{controller}': {String.Join(", ", stations)}."
                             : $"No charging station is known behind '{controller}': there is nobody to hand the next key pin before the switch.");

                #endregion

                #region 2. Every station: [current, next]

                var endpoints  = new Dictionary<String, (String Connection, UInt64 Version)>(StringComparer.Ordinal);
                var lacking    = new List<String>();

                foreach (var station in stations)
                {

                    CancellationToken.ThrowIfCancellationRequested();

                    var outcome = await HandOver(station, controller, [ current, next ], [ current, next ], null, LeaveWhereHeld: true);

                    outcomes.Add(outcome);
                    said.Add(Said(outcome));

                    if (outcome.Accepted && outcome.Connection is not null && outcome.Version is UInt64 version)
                        endpoints[station] = (outcome.Connection, version);
                    else
                        lacking.Add($"'{station}' ({outcome.Answer})");

                }

                #endregion

                #region 3. Every station has the next pin, or nothing is switched

                foreach (var (station, endpoint) in endpoints.ToArray())
                {

                    CancellationToken.ThrowIfCancellationRequested();

                    var (held, problem) = await ReadServerKeyPinsAsync(station, endpoint.Connection);

                    if (held is null)
                        lacking.Add($"'{station}' ({problem})");

                    else if (!held.Contains(next))
                        lacking.Add($"'{station}' (it holds {(held.Count > 0 ? String.Join(", ", held) : "no key pin")})");

                }

                if (lacking.Count > 0)
                {

                    said.Add($"{lacking.Count} charging station(s) do not have the next key pin: {String.Join("; ", lacking)}. " +
                             $"'{controller}' is not switched: a station without the next key pin could not connect again after it. " +
                              "Put that right and roll over again.");

                    Log.Warning(said.Last(), "ocpp", "keypins", "security");

                    return new KeyPinRun(false, said, outcomes);

                }

                said.Add(endpoints.Count > 0
                             ? $"Every station has the next key pin {next}."
                             : "There is no station to ask whether it has the next key pin.");

                #endregion

                #region 4. The switch

                var switched = await SwitchLocalController(controller, next);

                if (switched is not null)
                {
                    said.Add($"'{controller}' was not switched: {switched}");
                    Log.Warning(said.Last(), "ocpp", "keypins", "security");
                    return new KeyPinRun(false, said, outcomes);
                }

                said.Add($"'{controller}' presents its next key from its next handshake on; the stations connected to it stay connected.");

                Log.Notice($"The local controller '{controller}' was switched from the key pin {current} to {next}; " +
                           $"its {endpoints.Count} station(s) had the next key pin.", "ocpp", "keypins", "security");

                #endregion

                #region 5. After the grace period: [next]

                if (grace > TimeSpan.Zero)
                {

                    said.Add($"The old key pin {current} is taken away after {grace.TotalSeconds:0} second(s).");

                    try
                    {
                        await Task.Delay(grace, TimeProvider, CancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        said.Add($"Cut off before the old key pin was taken away: the stations hold {current} beside {next} until " +
                                 $"'keyPins confirm {controller}' takes it away.");
                        return new KeyPinRun(false, said, outcomes);
                    }

                }

                var failed = new List<String>();

                foreach (var (station, endpoint) in endpoints)
                {

                    var outcome = await SendPinSet(station, endpoint.Connection, [ next ], endpoint.Version + 1);

                    outcomes.Add(outcome);
                    said.Add(Said(outcome));

                    if (!outcome.Accepted)
                        failed.Add(station);

                }

                // What it presents now, for the store and the page.
                await ReadLocalControllerKeysAsync(controller);

                if (failed.Count > 0)
                {
                    said.Add($"{failed.Count} station(s) still hold the old key pin {current} beside {next}: {String.Join(", ", failed)}. " +
                             $"'keyPins confirm {controller}' takes it away once they answer.");
                    return new KeyPinRun(false, said, outcomes);
                }

                said.Add($"'{controller}' is rolled over to the key pin {next}.");

                return new KeyPinRun(true, said, outcomes);

                #endregion

            }
            finally
            {
                runLock.Release();
            }

        }

        #endregion

        #region KeyPinsJSON() / KeyPinsJSON(LocalController)

        /// <summary>
        /// The signing key's public part, and every Local Controller with the stations behind it.
        /// </summary>
        public JObject KeyPinsJSON()

            => new (
                   new JProperty("signer",            PinSetSigner.ToJSON()),
                   new JProperty("defaultGrace",      (Int32) DefaultRolloverGrace.TotalSeconds),
                   new JProperty("localControllers",  new JArray(KeyPins.All.Select(LocalControllerJSON)))
               );

        /// <summary>
        /// One Local Controller with the stations behind it, or null where none of that identity is known.
        /// </summary>
        public JObject? KeyPinsJSON(String LocalController)

            => KeyPins.Get(LocalController) is LocalControllerKeyPins controller
                   ? LocalControllerJSON(controller)
                   : null;

        private JObject LocalControllerJSON(LocalControllerKeyPins Controller)
        {

            var json = Controller.ToJSON();

            json.Add(new JProperty("connected",         IsConnected      (Controller.LocalController)));
            json.Add(new JProperty("inOverlayNetwork",  InOverlayNetwork (Controller.LocalController)));

            return json;

        }

        #endregion


        #region PinSetRequest(Station, Connection, Pins, Version, NetworkPath = null)

        /// <summary>
        /// A pin set for a station's endpoint, unsigned: one SetVariables of TLSClientController[&lt;connection&gt;]
        /// with ServerKeyPins - the pins, comma separated, in hexadecimal - and ServerKeyPinsVersion.
        /// </summary>
        public static OCPPv2_1_CSMS.SetVariablesRequest PinSetRequest(NetworkingNode_Id    Station,
                                                                      String               Connection,
                                                                      IEnumerable<KeyPin>  Pins,
                                                                      UInt64               Version,
                                                                      NetworkPath?         NetworkPath   = null)

            => new (
                   SourceRouting.To(Station),
                   [
                       new OCPPv2_1.SetVariableData(new OCPPv2_1.Component(TLSClientController, Connection),
                                                    new OCPPv2_1.Variable("ServerKeyPins"),
                                                    String.Join(",", Pins.Select(pin => pin.ToHex()))),
                       new OCPPv2_1.SetVariableData(new OCPPv2_1.Component(TLSClientController, Connection),
                                                    new OCPPv2_1.Variable("ServerKeyPinsVersion"),
                                                    Version.ToString(CultureInfo.InvariantCulture))
                   ],
                   NetworkPath: NetworkPath
               );

        #endregion

        #region (internal static) EndpointsIn(Report)

        /// <summary>
        /// The endpoints over TLS a station's report of TLSClientController names: every instance with a name,
        /// with what it holds.
        /// </summary>
        internal static IReadOnlyList<StationEndpoint> EndpointsIn(IEnumerable<OCPPv2_1.ReportData> Report)
        {

            var endpoints = new List<StationEndpoint>();

            foreach (var instance in Report.Where (data => data.Component.Name == TLSClientController && !String.IsNullOrEmpty(data.Component.Instance)).
                                            GroupBy(data => data.Component.Instance!))
            {

                var values = new Dictionary<String, String?>(StringComparer.OrdinalIgnoreCase);

                foreach (var data in instance)
                    values[data.Variable.Name] = data.VariableAttributes.FirstOrDefault(attribute => attribute.Type is null || attribute.Type == OCPPv2_1.AttributeTypes.Actual)?.Value;

                KeyPin? Pin(String Variable)
                    => values.TryGetValue(Variable, out var text) && KeyPin.TryParse(text, out var pin) ? pin : null;

                endpoints.Add(new StationEndpoint(
                                  instance.Key,
                                  values.GetValueOrDefault("URL"),
                                  [.. (values.GetValueOrDefault("ServerKeyPins") ?? "").
                                          Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).
                                          Select(text => KeyPin.TryParse(text, out var pin) ? pin : null).
                                          OfType<KeyPin>()],
                                  UInt64.TryParse(values.GetValueOrDefault("ServerKeyPinsVersion"), NumberStyles.None, CultureInfo.InvariantCulture, out var version) ? version : 0,
                                  values.GetValueOrDefault("ServerKeyPinState"),
                                  Pin("LearnedKeyPin"),
                                  Pin("KeyPinShown")
                              ));

            }

            return endpoints;

        }

        #endregion

        #region (internal static) ChooseEndpoint(Endpoints, LocalControllerPins, Named, Known)

        /// <summary>
        /// The endpoint of a station that leads to its Local Controller: the one the station named, where it
        /// named one; the one that learned, was shown or holds one of the controller's key pins; the one this
        /// CSMS handed pins before; the only one on probation; the only one at all. Null where none can be told.
        /// </summary>
        internal static StationEndpoint? ChooseEndpoint(IReadOnlyList<StationEndpoint>  Endpoints,
                                                        IReadOnlyCollection<KeyPin>     LocalControllerPins,
                                                        String?                         Named,
                                                        String?                         Known)
        {

            if (Named is not null && Endpoints.FirstOrDefault(endpoint => endpoint.Connection == Named) is StationEndpoint named)
                return named;

            return Endpoints.FirstOrDefault(endpoint => endpoint.Learned is not null && LocalControllerPins.Contains(endpoint.Learned))
                ?? Endpoints.FirstOrDefault(endpoint => endpoint.Shown   is not null && LocalControllerPins.Contains(endpoint.Shown))
                ?? Endpoints.FirstOrDefault(endpoint => endpoint.ServerKeyPins.Any(LocalControllerPins.Contains))
                ?? Endpoints.FirstOrDefault(endpoint => endpoint.Connection == Known)
                ?? (Endpoints.Where(endpoint => endpoint.Learned is not null).ToArray() is [ var learning ] ? learning : null)
                ?? (Endpoints.Count == 1 ? Endpoints[0] : null);

        }

        #endregion


        #region (private) FromThisCSMS

        /// <summary>
        /// Where a request of this CSMS comes from: in the overlay network the frame says it, and a request that
        /// names nobody is answered to nobody.
        /// </summary>
        private NetworkPath FromThisCSMS
            => NetworkPath.From(csms01.Id);

        #endregion

        #region (private) WhyNotNow(LocalController)

        /// <summary>
        /// Why no pin set can go to the stations behind the given controller now - or null.
        /// </summary>
        private String? WhyNotNow(String LocalController)
        {

            if (!PinSetSigner.Exists)
                return "This CSMS has no signing key for pin sets, and a station takes no pin set it did not sign. Make one with " +
                       "'keyPins signer create' and give its public key to the stations as a pin set signer.";

            if (!IsConnected(LocalController))
                return $"The local controller '{LocalController}' is not connected.";

            if (!InOverlayNetwork(LocalController))
                return $"The local controller '{LocalController}' dials this CSMS in standard mode, in which the stations behind it cannot be " +
                        "addressed. Set \"networkingMode\": \"overlay\" in the csms section of its configuration and let it dial again.";

            return null;

        }

        #endregion

        #region (private) HandOver(Station, LocalController, Pins, ControllerPins, Named, LeaveWhereHeld)

        /// <summary>
        /// Find the station's endpoint to its controller, and hand it the given pins with a version above the
        /// one it holds - or leave it, where it holds exactly them, is not on probation, and that is wanted.
        /// </summary>
        private async Task<PinSetOutcome> HandOver(String                       Station,
                                                   String                       LocalController,
                                                   IReadOnlyList<KeyPin>        Pins,
                                                   IReadOnlyCollection<KeyPin>  ControllerPins,
                                                   String?                      Named,
                                                   Boolean                      LeaveWhereHeld)
        {

            var hex = Pins.Select(pin => pin.ToHex()).ToArray();

            var (endpoints, problem) = await ReadEndpointsAsync(Station);

            if (problem is not null)
                return new PinSetOutcome(Station, null, null, hex, false, problem);

            var endpoint = ChooseEndpoint(endpoints!, ControllerPins, Named, KeyPins.StationOf(Station)?.Connection);

            if (endpoint is null)
                return new PinSetOutcome(Station, null, null, hex, false,
                                         endpoints!.Count == 0
                                             ? "it has no endpoint over TLS"
                                             : $"none of its {endpoints!.Count} endpoints over TLS ({String.Join(", ", endpoints!.Select(endpoint => endpoint.Connection))}) " +
                                               $"can be told to lead to '{LocalController}': none learned, was shown or holds one of its key pins");

            KeyPins.NoteConnection(Station, endpoint.Connection, endpoint.Version);

            if (LeaveWhereHeld &&
                endpoint.State != "Learned" &&
                endpoint.ServerKeyPins.Count == Pins.Count &&
                endpoint.ServerKeyPins.All(Pins.Contains))
            {
                return new PinSetOutcome(Station, endpoint.Connection, endpoint.Version, hex, true, "has them already");
            }

            return await SendPinSet(Station, endpoint.Connection, Pins, endpoint.Version + 1);

        }

        #endregion

        #region (private) SendPinSet(Station, Connection, Pins, Version)

        /// <summary>
        /// Sign and send a pin set, note it, and say what the station answered.
        /// </summary>
        private async Task<PinSetOutcome> SendPinSet(String                 Station,
                                                     String                 Connection,
                                                     IReadOnlyList<KeyPin>  Pins,
                                                     UInt64                 Version)
        {

            var hex = Pins.Select(pin => pin.ToHex()).ToArray();

            if (!NetworkingNode_Id.TryParse(Station, out var id))
                return new PinSetOutcome(Station, Connection, Version, hex, false, $"'{Station}' is no identity of a networking node");

            var request = PinSetRequest(id, Connection, Pins, Version, FromThisCSMS);

            if (!PinSetSigner.TrySign(request, out var notSigned))
                return new PinSetOutcome(Station, Connection, Version, hex, false, $"not signed: {notSigned}");

            String   answer;
            Boolean  accepted;

            try
            {

                var response = await csms01.OCPP.OUT.SetVariables(request);

                if (response.Result.ResultCode != OCPPResultCode.OK)
                {
                    answer    = $"no answer: {WhyNot(response.Result)}";
                    accepted  = false;
                }

                else
                {

                    var results  = response.SetVariableResults.ToArray();
                    var refused  = results.FirstOrDefault(result => result.AttributeStatus != OCPPv2_1.SetVariableStatus.Accepted);

                    accepted     = results.Length == 2 && refused is null;
                    answer       = accepted
                                       ? "Accepted"
                                       : refused is not null
                                             ? $"{refused.AttributeStatus}" +
                                               (refused.AttributeStatusInfo is not null
                                                    ? $" {refused.AttributeStatusInfo.ReasonCode}: {refused.AttributeStatusInfo.AdditionalInfo}".TrimEnd(' ', ':')
                                                    : "")
                                             : $"{results.Length} result(s) for 2 entries";

                }

            }
            catch (Exception e)
            {
                answer    = $"failed: {e.Message}";
                accepted  = false;
            }

            KeyPins.NoteSent(Station, Connection, Version, hex, TimeProvider.GetUtcNow(), answer, accepted);

            if (accepted)
                Log.Info   ($"The charging station '{Station}' took the pin set of version {Version} for its endpoint '{Connection}': {String.Join(", ", hex)}.",
                            "ocpp", "keypins", "security");
            else
                Log.Warning($"The charging station '{Station}' did not take the pin set of version {Version} for its endpoint '{Connection}': {answer}",
                            "ocpp", "keypins", "security");

            return new PinSetOutcome(Station, Connection, Version, hex, accepted, answer);

        }

        #endregion

        #region (private) ReadEndpointsAsync(Station)

        /// <summary>
        /// The station's endpoints over TLS, from its report of TLSClientController - or why there are none.
        /// </summary>
        private async Task<(IReadOnlyList<StationEndpoint>? Endpoints, String? Problem)> ReadEndpointsAsync(String Station)
        {

            if (!NetworkingNode_Id.TryParse(Station, out var id))
                return (null, $"'{Station}' is no identity of a networking node");

            var requestId  = Random.Shared.Next(1, Int32.MaxValue);
            var collector  = new ReportCollector();

            reports[(Station, requestId)] = collector;

            try
            {

                var response = await csms01.OCPP.OUT.GetReport(
                                         new OCPPv2_1_CSMS.GetReportRequest(
                                             SourceRouting.To(id),
                                             requestId,
                                             ComponentVariables:  [ new OCPPv2_1.ComponentVariable(new OCPPv2_1.Component(TLSClientController)) ],
                                             NetworkPath:         FromThisCSMS
                                         )
                                     );

                if (response.Result.ResultCode != OCPPResultCode.OK)
                    return (null, $"no answer to GetReport: {WhyNot(response.Result)}");

                if (response.Status != OCPPv2_1.GenericDeviceModelStatus.Accepted)
                    return (null, $"it answered GetReport of {TLSClientController} with {response.Status}" +
                                  (response.StatusInfo is not null ? $" ({response.StatusInfo.ReasonCode})" : ""));

                if (await Task.WhenAny(collector.Done.Task, Task.Delay(KeyPinReportPatience)) != collector.Done.Task)
                    return (null, $"it sent no report of {TLSClientController} within {KeyPinReportPatience.TotalSeconds:0} second(s)");

                lock (collector.Data)
                {
                    return (EndpointsIn([.. collector.Data]), null);
                }

            }
            catch (Exception e)
            {
                return (null, $"its report could not be had: {e.Message}");
            }
            finally
            {
                reports.TryRemove((Station, requestId), out _);
            }

        }

        #endregion

        #region (private) ReadServerKeyPinsAsync(Station, Connection)

        /// <summary>
        /// The key pins a station's endpoint holds now: GetVariables of TLSClientController[&lt;connection&gt;].ServerKeyPins.
        /// </summary>
        private async Task<(IReadOnlyList<KeyPin>? Pins, String? Problem)> ReadServerKeyPinsAsync(String  Station,
                                                                                                  String  Connection)
        {

            if (!NetworkingNode_Id.TryParse(Station, out var id))
                return (null, $"'{Station}' is no identity of a networking node");

            try
            {

                var response = await csms01.OCPP.OUT.GetVariables(
                                         new OCPPv2_1_CSMS.GetVariablesRequest(
                                             SourceRouting.To(id),
                                             [ new OCPPv2_1.GetVariableData(new OCPPv2_1.Component(TLSClientController, Connection),
                                                                            new OCPPv2_1.Variable("ServerKeyPins")) ],
                                             NetworkPath: FromThisCSMS
                                         )
                                     );

                if (response.Result.ResultCode != OCPPResultCode.OK)
                    return (null, $"no answer to GetVariables: {WhyNot(response.Result)}");

                var result = response.Results.FirstOrDefault();

                if (result is null || result.AttributeStatus != OCPPv2_1.GetVariableStatus.Accepted)
                    return (null, $"its {TLSClientController}[{Connection}].ServerKeyPins could not be read: {result?.AttributeStatus.ToString() ?? "no result"}");

                return ([.. (result.AttributeValue ?? "").
                                Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).
                                Select(text => KeyPin.TryParse(text, out var pin) ? pin : null).
                                OfType<KeyPin>()],
                        null);

            }
            catch (Exception e)
            {
                return (null, $"its key pins could not be read: {e.Message}");
            }

        }

        #endregion

        #region (private) SwitchLocalController(LocalController, Next)

        /// <summary>
        /// Tell a Local Controller to present its next key: SetVariables of EVQICtrlr[TLSServer].ActiveKeyPin.
        /// </summary>
        /// <returns>Null where it switched; why not otherwise.</returns>
        private async Task<String?> SwitchLocalController(String  LocalController,
                                                          KeyPin  Next)
        {

            if (!NetworkingNode_Id.TryParse(LocalController, out var id))
                return $"'{LocalController}' is no identity of a networking node";

            try
            {

                var response = await csms01.OCPP.OUT.SetVariables(
                                         new OCPPv2_1_CSMS.SetVariablesRequest(
                                             SourceRouting.To(id),
                                             [ new OCPPv2_1.SetVariableData(new OCPPv2_1.Component(EVQICtrlr, TLSServer),
                                                                            new OCPPv2_1.Variable("ActiveKeyPin"),
                                                                            Next.ToHex()) ],
                                             NetworkPath: FromThisCSMS
                                         )
                                     );

                if (response.Result.ResultCode != OCPPResultCode.OK)
                    return $"no answer to SetVariables: {WhyNot(response.Result)}";

                var result = response.SetVariableResults.FirstOrDefault();

                return result?.AttributeStatus == OCPPv2_1.SetVariableStatus.Accepted
                           ? null
                           : $"{result?.AttributeStatus.ToString() ?? "no result"}" +
                             (result?.AttributeStatusInfo is not null ? $" {result.AttributeStatusInfo.ReasonCode}: {result.AttributeStatusInfo.AdditionalInfo}" : "");

            }
            catch (Exception e)
            {
                return $"failed: {e.Message}";
            }

        }

        #endregion

        #region (private) CollectReport(Request)

        /// <summary>
        /// A part of a station's report, for whatever waits for it.
        /// </summary>
        private void CollectReport(OCPPv2_1_CS.NotifyReportRequest Request)
        {

            try
            {

                if (!reports.TryGetValue((Request.NetworkPath.Source.ToString(), Request.NotifyReportRequestId), out var collector))
                    return;

                lock (collector.Data)
                {
                    collector.Data.AddRange(Request.ReportData);
                }

                if (Request.ToBeContinued != true)
                    collector.Done.TrySetResult();

            }
            catch (Exception e)
            {
                Log.Exception(e, "A report of a charging station could not be taken in.", "ocpp", "keypins");
            }

        }

        #endregion

        #region (private static) WhyNot(Result)

        /// <summary>
        /// What went wrong with a request, as its result says it: its description, or its code where it has none.
        /// </summary>
        private static String WhyNot(OCPPv2_1.Result Result)

            => String.IsNullOrWhiteSpace(Result.Description)
                   ? Result.ResultCode.ToString()
                   : $"{Result.ResultCode}: {Result.Description}";

        #endregion

        #region (private static) Refused(Why) / Said(Outcome)

        private static KeyPinRun Refused(String Why)
            => new (false, [ Why ], []);

        private static String Said(PinSetOutcome Outcome)

            => Outcome.Accepted
                   ? Outcome.Answer == "Accepted"
                         ? $"'{Outcome.Station}' took the pin set of version {Outcome.Version} for its endpoint '{Outcome.Connection}': {String.Join(", ", Outcome.Pins)}."
                         : $"'{Outcome.Station}' {Outcome.Answer} on its endpoint '{Outcome.Connection}' (version {Outcome.Version}): {String.Join(", ", Outcome.Pins)}."
                   : $"'{Outcome.Station}' does not have the pins {String.Join(", ", Outcome.Pins)}: {Outcome.Answer}.";

        #endregion

        #region (private class) ReportCollector

        /// <summary>
        /// The parts of one report of one station, until the last.
        /// </summary>
        private sealed class ReportCollector
        {

            public List<OCPPv2_1.ReportData>  Data  { get; } = [];

            public TaskCompletionSource       Done  { get; } = new (TaskCreationOptions.RunContinuationsAsynchronously);

        }

        #endregion

    }

}
