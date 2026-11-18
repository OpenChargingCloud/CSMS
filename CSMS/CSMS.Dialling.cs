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

using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP;
using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.WebSockets;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

using cloud.charging.open.protocols.OCPP.Node;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

using OCPPv1_6 = cloud.charging.open.protocols.OCPPv1_6;
using OCPPv2_1 = cloud.charging.open.protocols.OCPPv2_1;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The charging stations, local controllers and gateways this CSMS dials: the ones
    /// that cannot dial it - behind a firewall that lets nothing out, on a
    /// network only the back end reaches - and have an OCPP server of their
    /// own for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OCPP stays as it is; only who opens the WebSocket is the other way
    /// round. What is dialled is written down as a connection, kept, dialled,
    /// followed and dialled again by what a charging station and a local
    /// controller dial their CSMS with (<see cref="WWCPNode"/>, over OCPP: <see cref="OCPPDialling"/>): the
    /// same store beside the configuration file, the same credentials and
    /// client identities, the same key pins and the same page.
    /// </para>
    /// <para>
    /// What is different is said here. What a CSMS dials is below it: a
    /// charging station, a local controller or a gateway, each of which it speaks to by
    /// its name - so a connection names the node at its other end, and is
    /// routed by that name and not as "the CSMS". It dials over ws:// and
    /// wss:// alone, in OCPP 2.1 alone, and writes down no connection the
    /// other end makes: what dials a CSMS are its charging stations, on the
    /// server it has for them.
    /// </para>
    /// <para>
    /// <b>A node that is dialled is a login of this CSMS all the same.</b>
    /// The name a connection leads to is the name of a login under Logins and
    /// groups: that is where a station is switched off, where a local
    /// controller or a gateway is marked as one - and so may send in the name
    /// of the stations behind it - and where its group says what it may do.
    /// To this CSMS a gateway is what a local controller is: spoken to in the
    /// overlay network, with the stations behind it reached through it. A
    /// connection to a login that is switched off is not dialled.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// What the certificate of a charging station or a local controller
        /// this CSMS dials is judged for, and what a root of the certificate
        /// store is kept for where it vouches for one.
        /// </summary>
        public const String  StationsCertificateUsage  = "stations";

        /// <summary>
        /// How long this CSMS waits before it dials a connection again that
        /// was lost or could not be made, at first and at most.
        /// </summary>
        public static readonly TimeSpan  RedialAfterAtFirst  = TimeSpan.FromSeconds(5);
        public static readonly TimeSpan  RedialAfterAtMost   = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Whether this CSMS dials: from when it started until it stops.
        /// </summary>
        private Boolean dials;

        #endregion

        #region (static) Constructor

        /// <summary>
        /// What the connections of this process say of the node they are
        /// the connections of: it is a CSMS.
        /// </summary>
        static CSMS()
        {
            NodeWording.Is("CSMS");
        }

        #endregion

        #region OCPPDialling / Nodes

        /// <summary>
        /// What OCPP says of the connections of this node.
        /// </summary>
        public OCPPDialling OCPPDialling
            => (OCPPDialling) Dialling;

        /// <summary>
        /// The OCPP nodes this one has: the one for OCPP 2.1, and before it
        /// the one for OCPP 1.6 where it speaks that.
        /// </summary>
        protected IEnumerable<cloud.charging.open.protocols.OCPP.NetworkingNode.AOCPPNetworkingNode> Nodes
            => OCPPDialling.Nodes;

        #endregion

        #region Node16 / Node21

        /// <summary>
        /// A CSMS dials in OCPP 2.1 alone.
        /// </summary>
        protected OCPPv1_6.NetworkingNode.AOCPPNetworkingNode? Node16
            => null;

        /// <summary>
        /// The node that speaks OCPP 2.1 for this CSMS.
        /// </summary>
        protected OCPPv2_1.NetworkingNode.AOCPPNetworkingNode Node21
            => csms01;

        #endregion

        #region ConnectionsCertificateUsage

        /// <summary>
        /// The certificate of a node this CSMS dials is judged for the use
        /// "stations".
        /// </summary>
        public override String ConnectionsCertificateUsage
            => StationsCertificateUsage;

        #endregion


        #region (private) BuildConnectionStores()

        /// <summary>
        /// The stores of what this CSMS dials - the connections and their
        /// credentials - beside the configuration file, and how it believes
        /// the servers of its connections by their key pins.
        /// </summary>
        private void BuildConnectionStores()
        {

            var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(ConfigFile.Path)) ?? ".";

            Connections = new ConnectionStore(
                              System.IO.Path.Combine(directory, ConnectionStore.DefaultDirectoryName),
                              TimeProvider
                          ) {

                              // What a CSMS dials is below it, and is spoken
                              // to by its name.
                              Rules = new ConnectionRules {
                                          Types                  = ConnectionRules.NodesBelow,
                                          Inbound                = false,
                                          SSH                    = false,
                                          OCPP1_6                = false,
                                          NamesTheNodeItLeadsTo  = true
                                      }

                          };

            keyPinning       = NewKeyPinning();
            OCPPDialling.MakeTLSClientSource();

            Connections.KnownCertificateIds     = () => Certificates.ByKind(CertificateKind.TLSIdentity).Select(entry => entry.Id);
            Connections.OnNotice               += (level, message) => Log.Log(level, message, "ocpp", "connections");

            // A node that is dialled is a login of this CSMS: where it is
            // switched off, marked as a local controller, and given a group.
            Connections.WhyItLeadsToNoSuchNode  = node => StationLogins?.TryGet(node, out _) == false
                                                              ? $"'{node}' is no login of this CSMS. A charging station or a local controller this CSMS " +
                                                                "dials is written down under Logins and groups as one that dials is, so that it " +
                                                                "can be switched off, marked as a local controller and given a group."
                                                              : null;

            Connections.OnConnectionsChanged   += () => {
                                                      if (dials)
                                                          _ = ApplyConnectionChanges();
                                                  };

            // A login switched off, or marked as a local controller: what is
            // dialled to it is let go of, or dialled as what it is now.
            StationLogins.OnChanged            += () => {
                                                      if (dials)
                                                          _ = ApplyConnectionChanges();
                                                  };

            // Never used to dial with - a CSMS dials over no ssh:// - and
            // made only when it is: what every node that dials has, for what
            // it shares with them.
            SshKey = new SshClientKey(
                         System.IO.Path.Combine(Connections.Path, SshClientKey.DirectoryName),
                         $"csms@{Environment.MachineName}"
                     );

            SshKey.OnNotice += (level, message) => Log.Log(level, message, "ocpp", "connections", "ssh", "security");

        }

        #endregion

        #region (private) DialTheNodesBelow() / HangUpOnTheNodesBelow()

        /// <summary>
        /// Dial every connection of the store that dials by itself.
        /// </summary>
        /// <remarks>
        /// Nothing here throws: a connection that cannot be made is a line in
        /// the log and a state the page shows, and the charging stations that
        /// dial are let in whether the others are reached or not.
        /// </remarks>
        private async Task DialTheNodesBelow()
        {

            dials = true;

            var dialled = Connections.Connections.Count(connection => connection.AutoConnect);

            if (dialled > 0)
                Log.Notice($"This CSMS dials {dialled} connection{(dialled == 1 ? "" : "s")} by itself: charging stations and local controllers " +
                            "that cannot dial it.",
                           "ocpp", "connections");

            try
            {
                await DialConfiguredConnections();
            }
            catch (Exception e)
            {
                Log.Warning($"The connections of this CSMS could not be dialled: {e.Message}", "ocpp", "connections");
            }

        }

        /// <summary>
        /// Hang up on everything this CSMS dialled.
        /// </summary>
        private async Task HangUpOnTheNodesBelow()
        {

            dials = false;

            try
            {
                await HangUp();
            }
            catch (Exception e)
            {
                Log.Warning($"Hanging up on what this CSMS dialled failed: {e.Message}", "ocpp", "connections");
            }

        }

        #endregion


        #region (protected override) NetworkingModeOf(Connection)

        /// <summary>
        /// A local controller and a gateway are spoken to in the overlay
        /// network, so that the charging stations behind them are reached
        /// through them; a charging station in the plain frame of OCPP.
        /// </summary>
        protected override NetworkingMode? NetworkingModeOf(ConnectionEntry Connection)

            => HasStationsBehind(Connection)
                   ? NetworkingMode.OverlayNetwork
                   : NetworkingMode.Standard;

        #endregion

        #region (protected override) ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken)

        /// <summary>
        /// Open the WebSocket of a connection: to a login of this CSMS that
        /// is switched on, and is what the connection says it is - and with
        /// what brings the connection back when it is lost.
        /// </summary>
        protected override Task<HTTPResponse> ConnectOverWebSocket(ConnectionEntry                                                 Connection,
                                                                   IHTTPAuthentication?                                            Basic,
                                                                   RemoteTLSServerCertificateValidationHandler<IWebSocketClient>?  Validator,
                                                                   X509Certificate2[]?                                             Certificates,
                                                                   TOTPConfig?                                                     TOTP,
                                                                   String?                                                         TOTPLogin,
                                                                   CancellationToken                                               CancellationToken)
        {

            if (WhyNotDialled(Connection) is String why)
                throw new InvalidOperationException(why);

            csms01.ReconnectPolicy ??= new WebSocketClientReconnectPolicy(
                                           InitialDelay:  RedialAfterAtFirst,
                                           MaxDelay:      RedialAfterAtMost
                                       );

            var connecting = base.ConnectOverWebSocket(Connection, Basic, Validator, Certificates, TOTP, TOTPLogin, CancellationToken);

            // The client of this dial is made, and among the clients of the
            // node, before anything of it is awaited: listened to here, it is
            // listened to before its first message.
            LogTheMessagesOf(Connection);

            return connecting;

        }

        #endregion

        #region (private) LogTheMessagesOf(Connection)

        /// <summary>
        /// The clients whose OCPP messages are logged already: a client is
        /// made for every dial, and listened to once.
        /// </summary>
        private readonly System.Runtime.CompilerServices.ConditionalWeakTable<Object, Object>  loggedClients = new ();

        /// <summary>
        /// The OCPP messages over a connection this CSMS dialled, in the log
        /// as the ones of a charging station that dialled in are: under the
        /// name the connection leads to, and by the same two switches - see
        /// <see cref="LogOCPPMessage"/>.
        /// </summary>
        /// <param name="Connection">A connection that is being dialled.</param>
        private void LogTheMessagesOf(ConnectionEntry Connection)
        {

            if (ClientOf(Connection) is not IWWCPWebSocketClient client ||
                !loggedClients.TryAdd(client, client))
            {
                return;
            }

            var node = Connection.RemoteNodeId ?? Connection.URL.ToString();

            client.OnJSONMessageReceived += (timestamp, sender, connection, eventTrackingId, messageTimestamp, sourceNodeId, message, cancellationToken) => {

                LogOCPPMessage("<-", node, message);
                return Task.CompletedTask;

            };

            client.OnJSONMessageSent += (timestamp, sender, connection, eventTrackingId, messageTimestamp, message, sentStatus, cancellationToken) => {

                LogOCPPMessage("->", node, message);
                return Task.CompletedTask;

            };

        }

        #endregion

        #region (protected override) WhatItIsDialledOn(Connection)

        /// <summary>
        /// A connection is dialled on what the login of the node it leads to
        /// says: changed, it is let go of and dialled again - or not dialled
        /// any more.
        /// </summary>
        protected override String? WhatItIsDialledOn(ConnectionEntry Connection)

            => WhyNotDialled(Connection) ?? "";

        #endregion

        #region WhyNotDialled(Connection)

        /// <summary>
        /// Why the given connection is not dialled although it is written
        /// down, or null where it is: what the login of the node it leads to
        /// says against it.
        /// </summary>
        public String? WhyNotDialled(ConnectionEntry Connection)
        {

            if (Connection.RemoteNodeId is not String node)
                return "it names no node at its other end";

            if (!StationLogins.TryGet(node, out var login))
                return $"'{node}' is no login of this CSMS any more";

            if (!login.Enabled)
                return $"the login '{node}' is switched off";

            var says  = WhatIsAt(Connection);
            var isA   = login.Kind ?? "charging station";

            if (says != isA)
                return Connection.ConnectionType switch {
                           ConnectionType.LocalController => $"the connection says a local controller is at its other end, and the login '{node}' is {AsMarked(login.Kind)}: " +
                                                             $"mark it, 'localControllers {node} on', or say that a {isA} is there",
                           ConnectionType.Gateway         => $"the connection says a gateway is at its other end, and the login '{node}' is {AsMarked(login.Kind)}: " +
                                                             $"mark it, 'gateways {node} on', or say that a {isA} is there",
                           _                              => $"the connection says a charging station is at its other end, and the login '{node}' is marked as a {isA}: " +
                                                             $"say that a {isA} is there, so that it is spoken to in the overlay network"
                       };

            return null;

        }

        #endregion

        #region WhyItsAnswersMayBeLost(Connection)

        /// <summary>
        /// What is to be known of a connection to a local controller or a gateway whose
        /// URL ends with another name than the one this CSMS has in OCPP, or
        /// null: it is dialled all the same, and warned of.
        /// </summary>
        /// <remarks>
        /// In the overlay network an answer is sent to the node that asked,
        /// by its name. A local controller that was dialled knows this CSMS
        /// by the name it came under; one of today learns the name it asks
        /// with as another name of that line, an older one does not - and
        /// then whatever this CSMS asks the controller or a station behind
        /// it is asked, and its answer goes nowhere: found against a real
        /// local controller. Which of the two is there cannot be seen from
        /// here, so it is said rather than refused.
        /// </remarks>
        /// <param name="Connection">A connection of this CSMS.</param>
        public String? WhyItsAnswersMayBeLost(ConnectionEntry Connection)

            => HasStationsBehind(Connection) &&
               ConnectionEntry.InboundNameOf(Connection.URL) is String comesUnder &&
               comesUnder != csms01.Id.ToString()

                   ? $"Its URL ends with '{comesUnder}', the name this CSMS comes under at the {WhatIsAt(Connection)}, and this CSMS is " +
                     $"'{csms01.Id}' in OCPP. A {WhatIsAt(Connection)} that does not learn the name it is asked with sends its answers, " +
                      "and the ones of the stations behind it, to a node it does not know: what this CSMS asks then runs into its " +
                      "timeout. Where that happens, make the two one - the name at the end of the URL, with the login it signs in " +
                     $"with, or \"ocpp\": {{ \"nodeId\": \"{comesUnder}\" }} in the configuration file - or update the {WhatIsAt(Connection)}."

                   : null;

        #endregion

        #region (protected override) ConnectionIsUp(Connection)

        /// <summary>
        /// A connection this CSMS dialled is up: said, as a charging station
        /// that dialled in is.
        /// </summary>
        protected override void ConnectionIsUp(ConnectionEntry Connection)
        {

            if (ocppServerSettings.Logging?.Connections != false)
                Log.Info($"The {WhatIsAt(Connection)} '{Connection.RemoteNodeId}' is reached at {Connection.URL}, which this CSMS dialled.",
                         "ocpp", "station", "connection");

            // Under another name than its own: connected, and said - on the
            // page, with how the connection stands, and as a warning.
            if (WhyItsAnswersMayBeLost(Connection) is String warning)
            {

                Note(Connection, $"Connected, and will come back by itself if it drops. {warning}");

                Log.Warning($"'{Connection.Description}' ({Connection.URL}): {warning}",
                            "ocpp", "station", "connection");

            }

        }

        #endregion

        #region DialledNodes / IsDialled(Node) / DialledAs(Node)

        /// <summary>
        /// The connection this CSMS dials the given node by, where it dials
        /// it and the connection is up.
        /// </summary>
        public ConnectionEntry? DialledAs(String Node)
        {

            var states = ConnectionStates;

            return Connections.Connections.FirstOrDefault(connection => !connection.Inbound &&
                                                                        connection.RemoteNodeId == Node &&
                                                                        states.TryGetValue(connection.Id, out var state) &&
                                                                        state.Status == ConnectionStatus.Connected);

        }

        /// <summary>
        /// Whether the given node is one this CSMS dials, up or not.
        /// </summary>
        public Boolean IsDialled(String Node)

            => Connections.Connections.Any(connection => !connection.Inbound && connection.RemoteNodeId == Node);

        /// <summary>
        /// The connections this CSMS dialled that are up, each with the node
        /// at its other end.
        /// </summary>
        public IReadOnlyList<ConnectionEntry> DialledNodes
        {
            get
            {

                var states = ConnectionStates;

                return [.. Connections.Connections.Where(connection => !connection.Inbound &&
                                                                       connection.RemoteNodeId is not null &&
                                                                       states.TryGetValue(connection.Id, out var state) &&
                                                                       state.Status == ConnectionStatus.Connected)];

            }
        }

        #endregion

        #region (private static) WhatIsAt(Connection) / HasStationsBehind(Connection) / AsMarked(Kind)

        private static String WhatIsAt(ConnectionEntry Connection)

            => Connection.ConnectionType switch {
                   ConnectionType.LocalController => "local controller",
                   ConnectionType.Gateway         => "gateway",
                   _                              => "charging station"
               };

        /// <summary>
        /// Whether a local controller or a gateway is at the other end of the
        /// given connection: a node with charging stations behind it.
        /// </summary>
        private static Boolean HasStationsBehind(ConnectionEntry Connection)

            => Connection.ConnectionType is ConnectionType.LocalController
                                         or ConnectionType.Gateway;

        private static String AsMarked(String? Kind)

            => Kind is null
                   ? "not marked as one"
                   : $"marked as a {Kind}";

        #endregion

    }

}
