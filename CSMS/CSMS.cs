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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.Configuration;
using cloud.charging.open.CSMS.Web;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// One CSMS: the OCPP node it speaks through, the HTTP server
    /// in front of it, the JSON API at "/api" and the web interface at "/".
    /// </summary>
    /// <remarks>
    /// The web interface is a bundle of HTML, CSS and JavaScript built by
    /// webpack from Frontend/ and embedded into this assembly, so that the
    /// CSMS is one file to deploy and needs nothing installed beside it.
    /// The browser and the CSMS talk over the JSON API and one
    /// Server-Sent Events stream; nothing is rendered on the server.
    ///
    /// A CSMS sits above the charging stations and the local controllers
    /// that dial into it, and is the thing they are all pointed at. That is
    /// what this web interface is for: it is the one place where somebody can
    /// see which of them got in, which were turned away and why, without
    /// reading a log file over somebody else's shoulder.
    ///
    /// What every one of these programs is before it is anything in
    /// particular - the log, the configuration file, name resolution and the
    /// time, the certificate store, the accounts, and the HTTP server with the
    /// web interface behind it - is the <see cref="WWCPNode"/> below. A CSMS
    /// is one of those with sections of its own in the same file, its own
    /// JSON API below "/api", a server on a port of its own for the charging
    /// stations, the OCPI endpoints its roaming partners call, and the OCPP
    /// node it speaks through.
    /// </remarks>
    public partial class CSMS : WWCPNode
    {

        #region Data

        /// <summary>
        /// The manifest resource prefix of the embedded frontend bundle
        /// (see the EmbedFrontend target of CSMS.csproj).
        /// </summary>
        public const String  HTTPRoot            = "cloud.charging.open.CSMS.HTTPRoot.";

        /// <summary>
        /// The TCP port the web interface listens on, unless another is given.
        /// </summary>
        /// <remarks>
        /// Next to the ports the other OpenChargingCloud boxes use - a charging
        /// station 2348 and 2349, a local controller 2350 - and not one of them:
        /// a CSMS, a controller and a station are routinely tried out on the
        /// same bench, and two web interfaces fighting over one socket is a
        /// confusing way to find that out. The node below has a port of its own
        /// for a node of no particular kind, and this one is handed to it rather
        /// than left to it.
        /// </remarks>
        public static new readonly IPPort DefaultHTTPPort = IPPort.Parse(2351);

        /// <summary>
        /// The port the charging stations connect to, as a sentence names it
        /// when it cannot be had: the other of the two things this CSMS
        /// listens for, beside <see cref="NodePort.WebInterface"/>.
        /// </summary>
        public static readonly NodePort  StationServerPort  = new ("The charging station server");

        /// <summary>
        /// What a line the libraries below write has to contain to be tagged,
        /// and with what: the table the debug bridge of a CSMS reads by.
        /// </summary>
        /// <remarks>
        /// What a CSMS overhears is mostly OCPP going past it in both
        /// directions, so the table leans that way: which side a line is
        /// about - this CSMS or one of the charging stations connected to it -
        /// is worth more here than which layer it came from. None of the
        /// vehicle's ISO 15118 and SLAC, which a CSMS never hears.
        /// </remarks>
        public static readonly IReadOnlyList<(String Needle, String Tag)> TraceTags = [
            ("ocpp",               "ocpp"),
            ("bootnotification",   "ocpp"),
            ("heartbeat",          "ocpp"),
            ("websocket",          "websocket"),
            ("http",               "http"),
            ("tls",                "tls"),
            ("certificate",        "tls"),
            ("dns",                "dns"),
            ("nts",                "nts"),
            ("ntp",                "nts"),
            ("csms",               "csms"),
            ("charging station",   "station"),
            ("chargingstation",    "station"),
            ("chargebox",          "station"),
            ("routing",            "routing"),
            ("forward",            "routing")
        ];

        /// <summary>
        /// The organization the accounts of this CSMS are in.
        /// </summary>
        /// <remarks>
        /// A CSMS on a bench has no organizations to speak of, and this one
        /// exists because the HTTPExt API's sign-in refuses an account that is
        /// in none - "You do not have access to any organization!" - however
        /// right its password is. So there is exactly one, named after the
        /// thing it stands for.
        /// </remarks>
        public const String  DefaultOrganization           = "CSMS";

        private readonly  OCPPv2_1_CSMS.TestCSMSNode  csms01;

        #endregion

        #region Properties

        /// <summary>
        /// Who this CSMS says it is when it speaks OCPP.
        /// </summary>
        /// <remarks>
        /// As it was read at the start. Unlike the name servers and the time
        /// server this is not changeable while running - see
        /// <see cref="OCPPConfiguration"/> for why an identification is a
        /// different kind of setting from an address.
        /// </remarks>
        public OCPPConfiguration      OCPP                   { get; }

        /// <summary>
        /// The OCPP 2.1 CSMS node this CSMS speaks through.
        /// </summary>
        public OCPPv2_1_CSMS.TestCSMSNode  Node
            => csms01;

        /// <summary>
        /// The JSON API at "/api/".
        /// </summary>
        public CSMSHTTPAPI            API                    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a CSMS with a web interface in front of it.
        /// Nothing listens yet: <see cref="WWCPNode.Start"/> does.
        /// </summary>
        /// <param name="DNSClient">The DNS client used by everything below.</param>
        /// <param name="NTSClient">The time client.</param>
        /// <param name="HTTPServer">An HTTP server to register within, or null to make one.</param>
        /// <param name="BasePath">What everything of this CSMS sits below; the root by default. Something else only where several of these programs share one HTTP server.</param>
        /// <param name="HTTPRootPath">The root path of the JSON API, "/api" below <paramref name="BasePath"/> by default.</param>
        /// <param name="ExtAPI">An HTTPExt API to sign in against, or null for one of this CSMS's own. Handing one in is what makes one sign-in open several of these programs at once.</param>
        /// <param name="AccountsPath">The directory the accounts live in between starts.</param>
        /// <param name="HTTPHostname">The address to listen on; the loopback address by default.</param>
        /// <param name="HTTPPort">The TCP port to listen on; <see cref="DefaultHTTPPort"/> by default.</param>
        /// <param name="ConfigFile">Where everything this CSMS can be told in writing lives: one file, whose sections the node below and the CSMS each read for themselves; "configuration.json" beside the process by default.</param>
        /// <param name="OCPP">Who this CSMS says it is in OCPP, unless the configuration file says otherwise.</param>
        /// <param name="OCPI">Who this CSMS is in OCPI, unless the configuration file says otherwise.</param>
        /// <param name="Frontend">Where the web interface comes from; the bundle embedded in this assembly by default.</param>
        /// <param name="Log">The event log; a new one by default.</param>
        /// <param name="LogToConsole">Whether the event log is also written to the console.</param>
        /// <param name="ConsoleLogLevel">What the console shows of it.</param>
        /// <param name="LogPath">The directory the log files are written to, or null to write none.</param>
        /// <param name="BridgeDebugLog">Whether what the libraries below write with DebugX ends up in the log.</param>
        /// <param name="TimeProvider">Where this CSMS reads the time; the system clock by default.</param>
        public CSMS(DNSClient?             DNSClient          = null,
                    NTSClient?             NTSClient          = null,
                    HTTPServer?            HTTPServer         = null,
                    HTTPPath?              BasePath           = null,
                    HTTPPath?              HTTPRootPath       = null,
                    HTTPExtAPI?            ExtAPI             = null,
                    String?                AccountsPath       = null,
                    IIPAddress?            HTTPHostname       = null,
                    IPPort?                HTTPPort           = null,
                    WWCPConfigFile?        ConfigFile         = null,
                    OCPPConfiguration?     OCPP               = null,
                    OCPIConfiguration?     OCPI               = null,
                    IStaticContentSource?  Frontend           = null,
                    EventLog?              Log                = null,
                    Boolean                LogToConsole       = true,
                    LogLevel               ConsoleLogLevel    = LogLevel.Info,
                    String?                LogPath            = null,
                    Boolean                BridgeDebugLog     = true,
                    TimeProvider?          TimeProvider       = null)

            // Every name as it was before there was a node below: the entries
            // about the CSMS itself are tagged "csms", the Server header says
            // "OpenChargingCloud CSMS", and a day's log file is
            // "csms-2026-09-25.log" - so that a log directory kept since then
            // goes on under the same names, and nothing reading one has to
            // learn a second. The organization is written into the accounts at
            // the first start and read back at every start after it, and must
            // never change at all.
            : base(Kind:              new NodeKind(
                                          Name:           "CSMS",
                                          Tag:            "csms",
                                          Product:        "CSMS",
                                          Organization:   DefaultOrganization,
                                          LogFilePrefix:  "csms"
                                      ),
                   Version:           typeof(CSMS).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
                   HTTPPort:          HTTPPort ?? DefaultHTTPPort,
                   HTTPHostname:      HTTPHostname,
                   HTTPServer:        HTTPServer,
                   BasePath:          BasePath,
                   HTTPRootPath:      HTTPRootPath,
                   ExtAPI:            ExtAPI,
                   AccountsPath:      AccountsPath,
                   Roles:             UserRole.All.Select(role => role.Name),
                   ConfigFile:        ConfigFile,
                   DNSClient:         DNSClient,
                   NTSClient:         NTSClient,
                   Frontend:          Frontend ?? new EmbeddedContentSource(HTTPRoot, typeof(CSMS).Assembly),

                   // None of the kinds the node's store keeps - those are
                   // ISO 15118's. What a CSMS presents and believes is its
                   // charging station server's, in stores of its own:
                   // ocpp-server-keys and ocpp-client-trust. So there is no
                   // store directory of the node's beside the configuration
                   // file either.
                   CertificateKinds:  [],

                   Log:               Log,
                   LogToConsole:      LogToConsole,
                   ConsoleLogLevel:   ConsoleLogLevel,
                   LogPath:           LogPath,
                   BridgeDebugLog:    BridgeDebugLog,
                   TraceTags:         TraceTags,
                   TimeProvider:      TimeProvider)

        {

            // "this." throughout, and not for tidiness: the parameters of this
            // constructor shadow the properties of the same name, and a
            // parameter such as "Log" or "ConfigFile" is null whenever the
            // caller did not bring one of its own.

            #region What the configuration file says about a CSMS

            // Its own sections of the document the node below has already
            // read: the ones that reading passed over are the ones this is
            // for. A file that is there but cannot be read has stopped the
            // node before this line; a section of it that is wrong stops the
            // CSMS here, for the same reason - somebody wrote down what their
            // CSMS is and got it wrong, and quietly running as something else
            // instead would be worse than stopping.
            if (!CSMSConfiguration.TryParse(ConfigurationDocument, out var configuration, out var problem))
                throw new InvalidOperationException($"'{this.ConfigFile.Path}': {problem} Repair or remove '{this.ConfigFile.Path}' and start again.");

            if (!configuration.IsEmpty)
                this.Log.Info($"CSMS configuration from '{this.ConfigFile.Path}': {configuration}.", "config");

            #endregion

            #region Who this CSMS says it is

            this.OCPP = configuration.OCPP
                            ?? OCPP
                            ?? new OCPPConfiguration();

            #endregion

            #region The JSON API

            this.Log.Info(
                OwnsExtAPI
                    ? $"The HTTPExt API is at '{this.ExtAPI.RootPath}', its accounts in '{this.ExtAPI.DatabaseFileName}'."
                    : $"This CSMS signs in against accounts it shares, at '{this.ExtAPI.RootPath}'.",
                "web", "http"
            );

            // The JSON API at "/api", beside the web interface the node below
            // has already put at "/". The more specific of the two, so that an
            // unknown /api path never reaches the single-page-application
            // stub.
            this.API           = new CSMSHTTPAPI(
                                     HTTPServer:  this.HTTPServer,
                                     CSMS:        this,
                                     ExtAPI:      this.ExtAPI,
                                     Log:         this.Log,
                                     APIPath:     this.HTTPRootPath,
                                     Version:     Version
                                 );

            #endregion

            #region The OCPP node

            csms01 = BuildOCPPNode(this.OCPP);

            this.Log.Info($"OCPP 2.1 CSMS '{csms01.Id}' is set up as {csms01.VendorName} {csms01.Model}.", "ocpp");

            #endregion

            #region The server the charging stations connect to

            // After the node, because it is attached to it, and after the
            // configuration file, because what it listens on is written there.
            // Nothing listens yet: OnListening does, once the node below has
            // its own port.
            BuildOCPPServer(configuration.OCPPServer);

            #endregion

            #region The OCPI endpoints the roaming partners call

            // After the HTTPExt API, because they hang off it, and after the
            // configuration file, because who this operator is in OCPI is
            // written there. They share the HTTP server above rather than
            // opening a port of their own: OCPI is plain HTTP, and one
            // operator is one address to point a partner at - and not the
            // port the charging stations dial into, which is the other
            // protocol entirely.
            BuildOCPI(configuration.OCPI ?? OCPI);

            #endregion

        }

        #endregion


        #region (protected override) OnListening()

        /// <summary>
        /// The charging stations' port, once the web interface has its own.
        /// </summary>
        /// <remarks>
        /// Before this CSMS calls itself started, so that a charging station
        /// server that cannot have its port ends the start rather than leaving
        /// a CSMS that says it is listening and that no station can reach. The
        /// socket layer throws the same exception for both servers, and its own
        /// words for it name neither the port nor what the port was for; both
        /// are known here. The node below lets go of the web interface's port
        /// again on the way out.
        /// </remarks>
        protected override async Task OnListening()
        {

            try
            {
                await StartOCPPServer();
            }
            catch (SocketException problem)
            {
                throw new PortUnavailableException(
                          ocppServerSettings.TCPPort ?? OCPPServerConfiguration.DefaultTCPPort,
                          problem,
                          StationServerPort
                      );
            }

        }

        #endregion

        #region (protected override) OnStarted()

        /// <summary>
        /// What a CSMS says once it is up: where its API is, and where its
        /// roaming partners find it.
        /// </summary>
        protected override Task OnStarted()
        {

            Log.Info   ($"The JSON API is at {APIURL}v1/status", "web", "http");
            Log.Notice ($"Roaming partners find this operator at {OCPIVersionsURL} " +
                        $"(OCPI {String.Join(", ", OCPIVersions.Select(version => version.Label))}, " +
                        $"{RemotePartyCount} partner(s), {LocationCount} location(s)).",
                        "ocpi");

            return Task.CompletedTask;

        }

        #endregion

        #region (protected override) OnStopping()

        /// <summary>
        /// End what this CSMS holds open beyond the web interface, before the
        /// server stops.
        /// </summary>
        protected override async Task OnStopping()
        {

            // Before the server, and that order is the whole point: every
            // browser with the Logs page open holds a request that is waiting
            // for the next log entry rather than for its socket, and the HTTP
            // server waits for every request it started. Closing the sockets
            // does not wake those, so they are ended here first - whoever owns
            // the server, because the streams are this CSMS's.
            API.CloseEventStreams();

            await StopOCPPServer();

        }

        #endregion


        #region ConfigurationJSON()

        /// <summary>
        /// What this CSMS is made of, as the Configuration page of the web
        /// interface reads it: what the node below says of itself, and on top
        /// the CSMS, its OCPP node, the server the charging stations connect
        /// to, the operator it is in OCPI and the assemblies it was built from.
        /// </summary>
        /// <remarks>
        /// Read-only: it answers "what am I running", not "change it". Nothing
        /// here is a secret - the accounts appear as the path they live at and
        /// the route to sign in, and never as anything about a password.
        /// </remarks>
        public override JObject ConfigurationJSON()
        {

            var json = base.ConfigurationJSON();

            // First, because it is the card the page leads with.
            json.AddFirst(new JProperty("CSMS", new JObject(
                              new JProperty("version",        Version),
                              new JProperty("createdAt",      CreatedAt.ToString("o")),
                              new JProperty("machine",        Environment.MachineName),
                              new JProperty("runtime",        Environment.Version.ToString()),
                              new JProperty("os",             Environment.OSVersion.ToString())
                          )));

            json.Add(new JProperty("ocpp",       new JObject(
                         new JProperty("version",          "2.1"),
                         new JProperty("role",             "CSMS"),
                         new JProperty("id",               csms01.Id.ToString()),
                         new JProperty("vendor",           csms01.VendorName),
                         new JProperty("model",            csms01.Model),
                         new JProperty("serialNumber",     csms01.SerialNumber),
                         new JProperty("softwareVersion",  csms01.SoftwareVersion),
                         new JProperty("file",             ConfigFile.Path)
                     )));

            json.Add(new JProperty("stationServer", new JObject(
                         new JProperty("enabled",          OCPPServerEnabled),
                         new JProperty("running",          ocppServerStarted),
                         new JProperty("tls",              ocppServerTLS),
                         new JProperty("url",              OCPPServerURL),
                         new JProperty("securityProfiles", new JArray((ocppServerSettings.SecurityProfiles ?? []).Select(profile => (Int32) profile))),
                         new JProperty("stationLogins",    StationLogins.EnabledCount),
                         new JProperty("trustedChains",    ClientTrust.EnabledCount),
                         new JProperty("certificates",     ServerCertificates.Entries.Count)
                     )));

            json.Add(new JProperty("ocpi",       new JObject(
                         new JProperty("role",             "CPO"),
                         new JProperty("partyId",          PartyIdText),
                         new JProperty("countryCode",      PartyId.CountryCode.ToString()),
                         new JProperty("party",            PartyId.PartyId.ToString()),
                         new JProperty("name",             BusinessDetails.Name),
                         new JProperty("website",          BusinessDetails.Website?.ToString()),
                         new JProperty("versions",         new JArray(OCPIVersions.Select(version => version.Label))),
                         new JProperty("versionsURL",      OCPIVersionsURL.ToString()),
                         new JProperty("partners",         RemotePartyCount),
                         new JProperty("locations",        LocationCount),
                         new JProperty("tokens",           TokenCount),
                         new JProperty("file",             ConfigFile.Path)
                     )));

            json.Add(new JProperty("assemblies", new JArray(
                         AssemblyJSON<HTTPServer>                              ("Hermod"),
                         AssemblyJSON<NTSClient>                               ("Norn"),
                         AssemblyJSON<WWCPNode>                                ("WWCP Node"),
                         AssemblyJSON<OCPPv2_1_CSMS.TestCSMSNode>              ("OCPP 2.1"),
                         AssemblyJSON<protocols.OCPI.CommonHTTPAPI>            ("OCPI"),
                         AssemblyJSON<protocols.OCPIv2_1_1.CommonAPI>          ("OCPI 2.1.1"),
                         AssemblyJSON<protocols.OCPIv2_2_1.CommonAPI>          ("OCPI 2.2.1"),
                         AssemblyJSON<protocols.OCPIv2_3_0.CommonAPI>          ("OCPI 2.3.0")
                     )));

            return json;

        }

        #endregion


        #region (private) BuildOCPPNode(Configuration)

        /// <summary>
        /// The OCPP 2.1 node this CSMS speaks through.
        /// </summary>
        /// <remarks>
        /// Every HTTP API the node brings of its own is switched off, and that
        /// is the one place where this differs from letting an
        /// <c>ACSMSNode</c> look after itself: left alone it would build a
        /// second HTTP server and a second HTTPExt API, on a port it picked,
        /// beside the ones the node below already made. One CSMS is one address
        /// to point a browser at - so the server and the HTTPExt API are the
        /// node's, made where the listening address, the port and the moment of
        /// starting are decided, and the OCPP node is handed a role rather than
        /// a socket.
        ///
        /// Nothing listens here either. Building the node and opening the port
        /// the charging stations come through are two different things, and the
        /// second one is not something a constructor should do on the way past.
        /// </remarks>
        private OCPPv2_1_CSMS.TestCSMSNode BuildOCPPNode(OCPPConfiguration Configuration)

            => new (

                   Id:                             NetworkingNode_Id.Parse(Configuration.NodeId     ?? OCPPConfiguration.DefaultNodeId),
                   VendorName:                     Configuration.VendorName                         ?? OCPPConfiguration.DefaultVendorName,
                   Model:                          Configuration.Model                              ?? OCPPConfiguration.DefaultModel,
                   SerialNumber:                   Configuration.SerialNumber,
                   SoftwareVersion:                Configuration.SoftwareVersion                    ?? Version,
                   Description:                    I18NString.Empty,

                   HTTPAPI_Disabled:               true,
                   HTTPAPI_EventLoggingDisabled:   true,
                   HTTPDownloadAPI_Disabled:       true,
                   HTTPUploadAPI_Disabled:         true,
                   WebAPI_Disabled:                true,
                   NTSServer_Disabled:             true,

                   ControlWebSocketServer:         null,

                   DisableSendHeartbeats:          true,
                   DisableMaintenanceTasks:        true,

                   DNSClient:                      this.DNSClient

               );

        #endregion

        #region (private static) AssemblyJSON<T>(Name)

        private static JObject AssemblyJSON<T>(String Name)
        {

            var assembly = typeof(T).Assembly.GetName();

            return new JObject(
                       new JProperty("name",      Name),
                       new JProperty("assembly",  assembly.Name),
                       new JProperty("version",   assembly.Version?.ToString(3))
                   );

        }

        #endregion

        #region DisposeAsync()

        /// <summary>
        /// Stop listening, let go of the stores of the charging station server,
        /// and then of what the node below holds.
        /// </summary>
        public override async ValueTask DisposeAsync()
        {

            // Stopped first, so that no charging station is still being let in
            // against a store that has already been let go of. The node below
            // stops again, which does no harm.
            await Stop();

            ServerCertificates?.Dispose();
            ClientTrust?       .Dispose();

            await base.DisposeAsync();

        }

        #endregion

    }

}
