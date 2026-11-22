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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.SSH;
using cloud.charging.open.protocols.WWCP.WebSockets;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.Logins;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

using cloud.charging.open.protocols.OCPP.Node.Serving;
using cloud.charging.open.protocols.OCPI.Transport;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The EMSPs that connect to this CSMS to speak OCPI over a WebSocket or
    /// over SSH: at the station port, by the subprotocols of OCPI, and at the
    /// subsystem "ocpi@open.charging.cloud" of the node's SSH server.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One port, as for every subprotocol.</b> The server of the station
    /// port listens, and hands a WebSocket that asks for "ocpi2.2.1" or the like
    /// to a server of OCPI of that version - attached to the networking node of
    /// OCPI of this CSMS, which has no port of its own -, as it hands one of
    /// OCPP 1.6 to the node of OCPP 1.6. Over SSH the subsystem of OCPI hands a
    /// HELLO to the server of the version it asks for.
    /// </para>
    /// <para>
    /// <b>An EMSP that connects is written down as a connection</b> of the type
    /// "EMSP", one the other end makes, of its version of OCPI - and nothing
    /// else gets in over OCPI. It signs in with a WebSocket login of this CSMS,
    /// by the same checks as at the station port (<see cref="WebSocketSignIns"/>,
    /// over the same logins and the same accepted chains), and over SSH as a
    /// station does - but for the subsystem of OCPI alone.
    /// </para>
    /// <para>
    /// <b>The one or the other.</b> A charging station does not come in over
    /// OCPI - a login that is no EMSP written down is turned away there -, and
    /// an EMSP does not come in as a charging station over OCPP: the name of a
    /// connection of OCPI is that connection's (see OCPPServingNode.LetInAsStation),
    /// and over SSH it opens the subsystem of OCPI and no other.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// What OCPI over SSH is called in what the SSH server says.
        /// </summary>
        public const String OCPIOverSSHLabel = "OCPI";

        /// <summary>
        /// What the door of OCPI at the station port calls the port and who
        /// comes to it.
        /// </summary>
        public static readonly WebSocketSignInWords EMSPWords = new () {
                                                                    Port            = "the station port",
                                                                    Who             = "An EMSP",
                                                                    PinnedLogin     = "the EMSP",
                                                                    Realm           = "OCPI",
                                                                    Tags            = [ "ocpi", "emsp" ],
                                                                    InboundTags     = [ "ocpi", "emsp" ]
                                                                };

        /// <summary>
        /// The WebSocket servers of OCPI behind the station port, by the version
        /// they speak.
        /// </summary>
        private readonly List<(String Version, WWCPWebSocketServer Server)>  ocpiServers     = [];

        /// <summary>
        /// The servers of OCPI over SSH, by the version they speak.
        /// </summary>
        private readonly List<(String Version, WWCPSshServer Server)>        ocpiSshServers  = [];

        private volatile Boolean  ocpiServed;
        private volatile Boolean  ocpiOverSSHServed;

        #endregion

        #region Properties

        /// <summary>
        /// Who comes in over OCPI at the station port: the sign-in checks of its
        /// door, over the WebSocket logins of this CSMS.
        /// </summary>
        public WebSocketSignIns                  OCPISignIns     { get; private set; } = default!;

        /// <summary>
        /// The WebSocket servers of OCPI behind the station port, one per version.
        /// </summary>
        public IEnumerable<WWCPWebSocketServer>  OCPIServers
        {
            get
            {
                lock (ocpiServers)
                    return [.. ocpiServers.Select(served => served.Server)];
            }
        }

        /// <summary>
        /// The servers of OCPI over SSH, one per version.
        /// </summary>
        public IEnumerable<WWCPSshServer>        OCPISshServers
        {
            get
            {
                lock (ocpiSshServers)
                    return [.. ocpiSshServers.Select(served => served.Server)];
            }
        }

        /// <summary>
        /// Whether an EMSP may connect over the SSH subsystem of OCPI right now.
        /// </summary>
        public Boolean                           OCPIOverSSHServed
            => ocpiOverSSHServed;

        #endregion


        #region (private) BuildTheDoorOfTheEMSPs()

        /// <summary>
        /// The servers of OCPI behind the station port and on the subsystem of
        /// OCPI, and their door. Nothing is let in yet.
        /// </summary>
        /// <remarks>
        /// After the station server, which hands them their WebSockets, and after
        /// the networking node of OCPI, which they are attached to.
        /// </remarks>
        private void BuildTheDoorOfTheEMSPs()
        {

            OCPISignIns = new WebSocketSignIns(
                              Logins:               WebSocketLogins,
                              ClientTrust:          ClientTrust,
                              SignInBrake:          SignInBrake,
                              Log:                  Log,
                              Authentications:      () => OCPPServerSettings.ClientAuthentication ?? WebSocketServerConfiguration.DefaultClientAuthentication,
                              OverTLS:              () => OCPPServerTLS,
                              ChecksRevocation:     () => OCPPServerSettings.CheckCertificateRevocation == true,
                              SaysSignIns:          () => OCPPServerSettings.Logging?.Authentication != false,
                              InboundConnectionOf:  (server, name) => VersionOf(server) is String version
                                                                          ? InboundConnectionOf(ProtocolVersion.OCPI(version), name)
                                                                          : null,
                              LetInAsInbound:       LetInAsInbound,
                              LetInOthers:          (connection, login, how, detail, byCertificate) =>
                                                        $"'{login}' is no EMSP that connects to this CSMS: no connection of OCPI is written down that comes under that name",
                              Words:                EMSPWords
                          );

            WebSocketLogins.OnChanged += () => {
                foreach (var server in OCPIServers)
                    OCPISignIns.ApplyLogins(server);
            };

            if (StationServer is not { } stationServer)
                return;

            var versions = OCPIVersions.Select (version => version.Label).
                                        Where  (OCPIWireNames.Versions.Contains).
                                        ToArray();

            foreach (var version in versions)
            {

                // Never started: it has no port of its own, and is handed its
                // WebSockets by the station port.
                var server = OCPINetworkingNode.AttachWebSocketServer(
                                 HTTPServiceName:        $"OpenChargingCloud {Kind.Product} v{Version}",
                                 IPAddress:              OCPPServerSettings.Address,
                                 TCPPort:                OCPPServerSettings.TCPPort,
                                 Description:            I18NString.Create($"The EMSPs of OCPI {version} of this CSMS"),
                                 RequireAuthentication:  false,
                                 SecWebSocketProtocols:  OCPIWireNames.SubprotocolsOf(version)
                             );

                OCPISignIns.Guard(server);

                stationServer.RouteBySubprotocol(server);

                lock (ocpiServers)
                    ocpiServers.Add((version, server));

                lock (ocpiSshServers)
                    ocpiSshServers.Add((version, OCPINetworkingNode.AttachSshServer(version)));

            }

        }

        #endregion

        #region (private) ServeTheEMSPsThatConnect() / StopServingTheEMSPsThatConnect(Why)

        /// <summary>
        /// Let in the EMSPs that connect: over the station port while it runs,
        /// and over SSH while OCPP-over-SSH is served.
        /// </summary>
        private void ServeTheEMSPsThatConnect()
        {

            if (ocpiServed || !OCPPServerRunning)
                return;

            ocpiServed = true;

            foreach (var (version, server) in ocpiServers.ToArray())
                ServeInbound(ProtocolVersion.OCPI(version), server);

            if (!OCPPOverSSHServed || ocpiSshServers.Count == 0)
                return;

            // Before the subsystem is there, so that an EMSP asking for it the
            // moment it is finds itself let in.
            ocpiOverSSHServed = true;

            var sshServers = OCPISshServers.ToArray();

            try
            {
                AddSSHSubsystem(new SSHSubsystem(
                                    OCPIWireNames.SshSubsystem,
                                    OCPIOverSSHLabel,
                                    sshServers.Length == 1
                                        ? sshServers[0].Handler
                                        : SshMessageServer.RoutedBySubprotocol([.. sshServers.Select(server => server.MessageServer)])
                                ));
            }
            catch (Exception e)
            {
                ocpiOverSSHServed = false;
                Log.Critical($"OCPI over SSH could not be served: {e.Message}", "ocpi", "emsp", "ssh");
                return;
            }

            foreach (var (version, server) in ocpiSshServers.ToArray())
                ServeInbound(ProtocolVersion.OCPI(version), server);

        }

        /// <summary>
        /// Let no EMSP in any more, and let go of those that are.
        /// </summary>
        /// <param name="Why">Why, as the other end is told.</param>
        private async Task StopServingTheEMSPsThatConnect(String Why)
        {

            if (!ocpiServed)
                return;

            ocpiServed = false;

            if (ocpiOverSSHServed)
            {

                ocpiOverSSHServed = false;

                foreach (var (version, _) in ocpiSshServers.ToArray())
                    StopServingInboundOverSSH(ProtocolVersion.OCPI(version), Why);

                RemoveSSHSubsystem(OCPIWireNames.SshSubsystem);

            }

            foreach (var (version, server) in ocpiServers.ToArray())
            {
                StopServingInbound(ProtocolVersion.OCPI(version), Why);
                await server.Shutdown(Why);
            }

        }

        #endregion

        #region (protected override) SSHSubsystemOfLogin(Login)

        /// <summary>
        /// An EMSP that connects over SSH opens the subsystem of OCPI, and no
        /// other: the login it signs in with is the name of a connection of OCPI.
        /// </summary>
        protected override String SSHSubsystemOfLogin(User_Id Login)

            => Connections?.Connections.Any(entry => entry.Inbound &&
                                                     entry.Use         == ConnectionUse.OCPI &&
                                                     entry.InboundName == Login.ToString()) == true
                   ? OCPIWireNames.SshSubsystem
                   : base.SSHSubsystemOfLogin(Login);

        #endregion

        #region (private) VersionOf(Server)

        /// <summary>
        /// The version of OCPI the given WebSocket server speaks, or null where
        /// it is none of OCPI.
        /// </summary>
        private String? VersionOf(AWebSocketEndpoint Server)
        {
            lock (ocpiServers)
                return ocpiServers.FirstOrDefault(served => ReferenceEquals(served.Server, Server)).Version;
        }

        #endregion

    }

}
