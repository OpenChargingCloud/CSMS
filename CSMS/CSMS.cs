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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.NetworkingNode;

using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;

// Only the mailer, not the namespace: Hermod.SMTP carries a LogLevel of its
// own, and importing it would make every LogLevel in this file ambiguous with
// the one the event log uses.
using NullMailer = org.GraphDefined.Vanaheimr.Hermod.SMTP.NullMailer;

using cloud.charging.open.CSMS.Configuration;
using cloud.charging.open.CSMS.Logging;
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
    /// </remarks>
    public partial class CSMS : IAsyncDisposable
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
        /// confusing way to find that out.
        /// </remarks>
        public static readonly IPPort DefaultHTTPPort = IPPort.Parse(2351);

        /// <summary>
        /// Where the HTTPExt API - users, organizations, API keys - lives,
        /// unless another path is given.
        /// </summary>
        /// <remarks>
        /// Below a path of its own rather than at "/", because three things
        /// share this server: the JSON API of this CSMS at "/api", the web
        /// interface at "/", and this. The web interface is the catch-all of
        /// the three, so everything that is not it needs a prefix that says
        /// so before the stub gets the request.
        /// </remarks>
        public static readonly HTTPPath DefaultHTTPExtAPIPath = HTTPPath.Parse("/ext");

        /// <summary>
        /// The directory the HTTPExt API keeps its accounts in, unless another
        /// is given.
        /// </summary>
        /// <remarks>
        /// A directory and not a file, because the HTTPExt API writes more than
        /// one: the accounts themselves, the passwords, the sessions and the
        /// password resets all live below it, and it names them itself. What is
        /// chosen here is only where that tree starts.
        /// </remarks>
        public const String  DefaultHTTPExtAPIDataPath     = "CSMS-accounts";

        /// <summary>
        /// The file inside that directory that holds the accounts.
        /// </summary>
        public const String  DefaultHTTPExtAPIDatabaseFile = "CSMS-accounts.db";

        /// <summary>
        /// The file of the bundle that is the web interface; its presence is
        /// what says there is one to serve at all.
        /// </summary>
        public const String  IndexFile           = "index.html";

        /// <summary>
        /// The icon of the bundle, which /favicon.ico is pointed at.
        /// </summary>
        public const String  FaviconSVG          = "favicon.svg";

        private readonly  DNSClient                       dnsClient;
        private           NTSClient                       ntsClient;

        /// <summary>
        /// The name servers this CSMS would ask, whether or not
        /// name resolution is switched on at the moment.
        /// </summary>
        /// <remarks>
        /// Kept beside the DNS client because switching name resolution off is
        /// done by taking its servers away - which is what being switched off
        /// actually means, for everything holding that client and not only for
        /// the parts of this CSMS that remember to ask first. Switching
        /// it back on needs the list back, and this is where it waited.
        /// </remarks>
        private           IReadOnlyList<DNSServerConfig>  configuredDNSServers;

        /// <summary>
        /// Serialises changes to what this CSMS is made of, so that
        /// two browsers saving at the same moment do not build half a
        /// CSMS each.
        /// </summary>
        private readonly  SemaphoreSlim                   reconfigureLock = new (1, 1);

        private readonly  HTTPServer                      httpServer;
        private readonly  HTTPPath                        httpRootPath;

        /// <summary>
        /// When this CSMS last managed to check its clock, what it
        /// found, and against whom.
        /// </summary>
        /// <remarks>
        /// Three fields rather than one object because they are written from
        /// one place and read from another, and the alternative - digging them
        /// back out of the JSON of the last check - would make every reader
        /// depend on the shape of a diagnostic.
        /// </remarks>
        private           DateTimeOffset?                 lastTimeCheck;
        private           TimeSpan?                       lastTimeCheckOffset;
        private           String?                         lastTimeCheckServer;

        /// <summary>
        /// The clock that makes this CSMS check its own, when NTS
        /// is on.
        /// </summary>
        private           ITimer?                         timeCheckTimer;

        /// <summary>
        /// What the file said about the time client, kept because the parts of
        /// it that are not the client itself - how often to check, and what the
        /// operator claims about the server - are read long afterwards.
        /// </summary>
        private           NTSConfiguration?               ntsSettings;

        private readonly  ConsoleLog?                     consoleLog;
        private readonly  TraceBridge?                    traceBridge;

        private readonly  OCPPv2_1_CSMS.TestCSMSNode  csms01;

        private           Boolean                         started;

        #endregion

        #region Properties

        /// <summary>
        /// Everything that happens inside this CSMS.
        /// </summary>
        public EventLog               Log                    { get; }

        /// <summary>
        /// Who may open the web interface, and which browsers currently may.
        /// </summary>
        public WebSessions            Sessions               { get; }

        /// <summary>
        /// Where the web login lives between starts.
        /// </summary>
        public WebLoginFile           LoginFile              { get; }

        /// <summary>
        /// Where everything this CSMS can be told in writing lives
        /// between starts: its name resolution, its time source, its OCPP
        /// identification.
        /// </summary>
        public CSMSConfigFile   ConfigFile             { get; }

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
        /// How this CSMS resolves names.
        /// </summary>
        public DNSClient              DNSClient
            => dnsClient;

        /// <summary>
        /// Where this CSMS reads the time.
        /// </summary>
        /// <remarks>
        /// Replaced rather than reconfigured when it is pointed at another
        /// server: an NTS client is bound to its host at construction, and the
        /// cookies and keys it holds belong to that host and to no other.
        /// </remarks>
        public NTSClient              NTSClient
            => ntsClient;

        /// <summary>
        /// Whether this CSMS resolves names at all.
        /// </summary>
        /// <remarks>
        /// Switched off by taking the name servers away from the DNS client, so
        /// that it is off for everything that was handed that client - not only
        /// for the parts of this CSMS that would have remembered to check
        /// a flag first. A query then fails at once and says why.
        /// </remarks>
        public Boolean                DNSEnabled             { get; private set; } = true;

        /// <summary>
        /// Whether this CSMS may ask its time server.
        /// </summary>
        public Boolean                NTSEnabled             { get; private set; } = true;

        /// <summary>
        /// The password this CSMS made up because there was no
        /// login file, or null when the login came from the file. It is shown
        /// once, on the console, and kept nowhere but in its hash.
        /// </summary>
        public String?                GeneratedPassword      { get; }

        /// <summary>
        /// Where the web interface comes from: this assembly, or a directory
        /// on disk.
        /// </summary>
        public IStaticContentSource   Frontend               { get; }

        /// <summary>
        /// The HTTP server everything below is registered within.
        /// </summary>
        public HTTPServer             HTTPServer
            => httpServer;

        /// <summary>
        /// The HTTPExt API at "/ext/": the users, organizations and API keys
        /// this CSMS is administered with.
        /// </summary>
        /// <remarks>
        /// This is where a CSMS parts company with a charging station or a
        /// local controller, which carry one web login each and are done with
        /// it. A CSMS is the back end of an estate: the people who read it are
        /// not the people who configure it, the machines that call it are not
        /// people at all, and both outlive any one of its operators. That is
        /// what Hermod's HTTPExt API is - accounts, groups, organizations and
        /// API keys, kept in its own database file - and building a second,
        /// smaller version of it here would only mean having two.
        /// </remarks>
        public HTTPExtAPI             ExtAPI                 { get; }

        /// <summary>
        /// The JSON API at "/api/".
        /// </summary>
        public CSMSHTTPAPI            API                    { get; }

        /// <summary>
        /// The web interface at "/", or null when no bundle was found to serve.
        /// </summary>
        public HTTPAPI?               WebInterface           { get; }

        /// <summary>
        /// The URL to open in a browser.
        /// </summary>
        public URL                    WebInterfaceURL        { get; }

        /// <summary>
        /// The version of this CSMS.
        /// </summary>
        public String                 Version                { get; }

        /// <summary>
        /// Where this CSMS reads the time.
        /// </summary>
        /// <remarks>
        /// A CSMS is the clock of everything below it: it is what
        /// a charging station without a time source of its own is told the time
        /// by, and what the records passing through it are stamped against. So
        /// the clock is something to be handed in rather than reached for. The
        /// system clock by default; an NTS-disciplined or a fake one where a
        /// test or a calibration says so.
        /// </remarks>
        public TimeProvider           TimeProvider           { get; }

        /// <summary>
        /// When this CSMS was created, by its own clock.
        /// </summary>
        public DateTimeOffset         CreatedAt              { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a CSMS with a web interface in front of it.
        /// Nothing listens yet: <see cref="Start"/> does.
        /// </summary>
        /// <param name="DNSClient">The DNS client used by everything below.</param>
        /// <param name="NTSClient">The time client.</param>
        /// <param name="HTTPServer">An HTTP server to register within, or null to make one.</param>
        /// <param name="HTTPRootPath">The root path of the JSON API, "/api" by default.</param>
        /// <param name="HTTPExtAPIPath">The root path of the HTTPExt API, "/ext" by default.</param>
        /// <param name="HTTPExtAPIDataPath">The directory the HTTPExt API keeps its users, organizations and API keys in.</param>
        /// <param name="HTTPHostname">The address to listen on; the loopback address by default.</param>
        /// <param name="HTTPPort">The TCP port to listen on.</param>
        /// <param name="LoginFile">Where the web login lives; "web-login.json" beside the process by default.</param>
        /// <param name="ConfigFile">Where everything this CSMS can be told in writing lives; "configuration.json" beside the process by default.</param>
        /// <param name="OCPP">Who this CSMS says it is in OCPP, unless the configuration file says otherwise.</param>
        /// <param name="Frontend">Where the web interface comes from; the bundle embedded in this assembly by default.</param>
        /// <param name="Log">The event log; a new one by default.</param>
        /// <param name="LogToConsole">Whether the event log is also written to the console.</param>
        /// <param name="ConsoleLogLevel">What the console shows of it.</param>
        /// <param name="BridgeDebugLog">Whether what the libraries below write with DebugX ends up in the log.</param>
        /// <param name="TimeProvider">Where this CSMS reads the time; the system clock by default.</param>
        public CSMS(DNSClient?             DNSClient               = null,
                    NTSClient?             NTSClient               = null,
                    HTTPServer?            HTTPServer              = null,
                    HTTPPath?              HTTPRootPath            = null,
                    HTTPPath?              HTTPExtAPIPath          = null,
                    String?                HTTPExtAPIDataPath      = null,
                    IIPAddress?            HTTPHostname            = null,
                    IPPort?                HTTPPort                = null,
                    WebLoginFile?          LoginFile               = null,
                    CSMSConfigFile?        ConfigFile              = null,
                    OCPPConfiguration?     OCPP                    = null,
                    IStaticContentSource?  Frontend                = null,
                    EventLog?              Log                     = null,
                    Boolean                LogToConsole            = true,
                    LogLevel               ConsoleLogLevel         = LogLevel.Info,
                    Boolean                BridgeDebugLog          = true,
                    TimeProvider?          TimeProvider            = null)
        {

            #region The clock, before anything that wants to know the time

            // First of all, and not for tidiness: the event log below stamps
            // every entry with this, so a clock set afterwards would leave the
            // log reading the system one - and a log on a different clock than
            // the CSMS it belongs to cannot be held against anything.
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;
            this.CreatedAt     = this.TimeProvider.GetUtcNow();

            #endregion

            #region The log, next - everything below it may want to say something

            this.Version      = typeof(CSMS).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
            this.Log          = Log ?? new EventLog(TimeProvider: this.TimeProvider);

            this.consoleLog   = LogToConsole
                                    ? new ConsoleLog(this.Log, ConsoleLogLevel)
                                    : null;

            // Attached before anything else is built, so that what the DNS
            // client, the HTTP server and the OCPP node say while they are
            // being made is already in the log a browser will see later.
            this.traceBridge  = BridgeDebugLog
                                    ? TraceBridge.Attach(this.Log)
                                    : null;

            this.Log.Notice($"CSMS v{this.Version} starting up.", "csms");

            #endregion

            #region Who may open the web interface

            this.LoginFile = LoginFile ?? new WebLoginFile(WebLoginFile.DefaultFileName);

            if (this.LoginFile.TryLoad(out var loadedLogin, out var loginError) && loadedLogin is not null)
                this.Sessions = new WebSessions(loadedLogin,   TimeProvider: this.TimeProvider);

            else
            {

                // A login file that is there but unreadable is not something to
                // paper over with a new password: that would lock out whoever
                // owns the old one without saying why.
                if (loginError is not null)
                    throw new InvalidOperationException($"{loginError} Repair or remove '{this.LoginFile.Path}' and start again.");

                // A first start: nobody can sign in to a web interface whose
                // login is not set yet, and an unauthenticated setup page would
                // be a door of its own. So the password is made up here and
                // shown once, on the console, to whoever started the process.
                var (generated, password) = WebLoginSettings.Generate();

                this.LoginFile.Save(generated);

                this.Sessions           = new WebSessions(generated, TimeProvider: this.TimeProvider);
                this.GeneratedPassword  = password;

                this.Log.Notice($"No web login found, so one was made up and written to '{this.LoginFile.Path}'.", "web", "auth");

            }

            #endregion

            #region What the configuration file says

            this.ConfigFile = ConfigFile ?? new CSMSConfigFile(CSMSConfigFile.DefaultFileName);

            CSMSConfiguration? configuration = null;

            if (this.ConfigFile.Exists)
            {

                // A file that is there but cannot be read is not something to
                // paper over with defaults: somebody wrote down what their
                // CSMS is and got it wrong, and quietly running as
                // something else instead would be worse than stopping.
                if (!this.ConfigFile.TryLoad(out configuration, out var configError))
                    throw new InvalidOperationException($"{configError} Repair or remove '{this.ConfigFile.Path}' and start again.");

                this.Log.Info($"Configuration from '{this.ConfigFile.Path}': {configuration}.", "config");

            }

            #endregion

            #region The clients everything below shares

            this.dnsClient             = DNSClient ?? new DNSClient();
            this.configuredDNSServers  = [.. dnsClient.DNSServers];

            // The clock goes to the time client too: a CSMS that reads
            // one clock itself and disciplines another would have two, which is
            // one more than anything below it can be told the time by.
            this.ntsClient     = NTSClient    ?? new NTSClient(
                                                     DomainName.Parse(NTSConfiguration.DefaultHostname),
                                                     Timeout:         TimeSpan.FromSeconds(10),
                                                     DNSClient:       dnsClient,
                                                     TimeProvider:    this.TimeProvider
                                                 );

            // Last, and that is the whole precedence rule: what this
            // constructor was handed holds until the file says otherwise, and
            // what the file does not mention is left exactly as it was.
            if (configuration?.DNS is not null)
                ApplyDNSConfiguration(configuration.DNS);

            if (configuration?.NTS is not null)
                ApplyNTSConfiguration(configuration.NTS);

            this.ntsSettings = configuration?.NTS;

            #endregion

            #region Who this CSMS says it is

            this.OCPP = configuration?.OCPP
                            ?? OCPP
                            ?? new OCPPConfiguration();

            #endregion

            #region The HTTP server, the JSON API and the web interface

            var address        = HTTPHostname ?? IPv4Address.Localhost;
            var port           = HTTPPort     ?? DefaultHTTPPort;

            this.httpServer    = HTTPServer   ?? new HTTPServer(
                                                     IPAddress:       address,
                                                     TCPPort:         port,
                                                     HTTPServerName:  $"OpenChargingCloud CSMS v{Version}",
                                                     DNSClient:       dnsClient
                                                 );

            this.httpRootPath  = HTTPRootPath ?? CSMSHTTPAPI.DefaultAPIPath;

            this.WebInterfaceURL = URL.Parse($"http://{address}:{port}/");

            // The HTTPExt API builds the paths of its files by putting strings
            // together rather than with Path.Combine, so a directory that does
            // not end in a separator would give it "...accountsUsersAPI" and
            // not "...accounts/UsersAPI". Ending it here is cheaper than
            // finding that out from the name of a file nobody meant to write.
            var extAPIDataPath = HTTPExtAPIDataPath ?? Path.Combine(AppContext.BaseDirectory, DefaultHTTPExtAPIDataPath);

            if (!extAPIDataPath.EndsWith(Path.DirectorySeparatorChar))
                extAPIDataPath += Path.DirectorySeparatorChar;

            // 1) The HTTPExt API at "/ext". First of the three, because it is
            //    the one with a database behind it: whatever it finds wrong
            //    with its files, it should say so before a port is opened and
            //    before a charging station is let in against accounts that
            //    were not read.
            this.ExtAPI        = new HTTPExtAPI(
                                     HTTPServer:             httpServer,
                                     RootPath:               HTTPExtAPIPath ?? DefaultHTTPExtAPIPath,
                                     HTTPServerName:         $"OpenChargingCloud CSMS v{Version}",
                                     HTTPServiceName:        $"OpenChargingCloud CSMS v{Version}",
                                     APIRobotEMailAddress:   EMailAddress.Parse("OpenChargingCloud CSMS Robot <robot@charging.cloud>"),
                                     APIRobotGPGPassphrase:  "",

                                     // Nothing here sends mail. A CSMS that
                                     // notifies by e-mail is told so by its
                                     // operator, with a submission client of
                                     // their own; until then a mailer that
                                     // swallows what it is given is better
                                     // than one that quietly retries against
                                     // a host nobody configured.
                                     SMTPSubmissionClient:   new NullMailer(),
                                     DisableNotifications:   true,

                                     LoggingPath:            extAPIDataPath,
                                     DatabaseFileName:       DefaultHTTPExtAPIDatabaseFile,

                                     // Left on, and that is what makes the
                                     // directory above: switching it off skips
                                     // the CreateDirectory that the accounts
                                     // file is written into, and the first
                                     // account created would fail on a path
                                     // that was never made.
                                     DisableLogging:         false
                                 );

            this.Log.Info($"The HTTPExt API is at '{(HTTPExtAPIPath ?? DefaultHTTPExtAPIPath)}', its accounts in '{ExtAPI.DatabaseFileName}'.", "web", "http");

            // 2) The JSON API at "/api". Before the web interface, so that it
            //    is the more specific API and an unknown /api path never
            //    reaches the single-page-application stub below.
            this.API           = new CSMSHTTPAPI(
                                     HTTPServer:  httpServer,
                                     CSMS:        this,
                                     Sessions:    Sessions,
                                     Log:         this.Log,
                                     APIPath:     httpRootPath,
                                     Version:     Version
                                 );

            // 3) The web interface at "/": the files of the bundle, and the
            //    single-page-application stub for every other page URL, so
            //    that a reload on /logs and a bookmark to it both work.
            this.Frontend      = Frontend ?? new EmbeddedContentSource(HTTPRoot, typeof(CSMS).Assembly);

            if (this.Frontend.TryGet(IndexFile, out _))
            {

                this.WebInterface = httpServer.AddHTTPAPI();

                this.WebInterface.MapSinglePageApplication(
                    this.Frontend,
                    new SinglePageAppOptions {
                        IndexTransform = html => html.Replace("{{ServerVersion}}", $"v{Version}", StringComparison.Ordinal)
                    }
                );

                // Browsers ask for /favicon.ico whatever the page says, and a
                // bundle built by webpack carries an SVG. A literal route wins
                // over the catch-all, so this answers before the stub would -
                // and beats a 404 on every visit, which is a line in the log
                // and a broken icon in the tab.
                if (this.Frontend.TryGet(FaviconSVG, out _))
                    this.WebInterface.AddHandler(
                        HTTPPath.Parse("/favicon.ico"),
                        request => Task.FromResult(
                                       new HTTPResponse.Builder(request) {
                                           HTTPStatusCode  = HTTPStatusCode.TemporaryRedirect,
                                           Location        = Location.From(HTTPPath.Parse("/" + FaviconSVG)),
                                           CacheControl    = "public, max-age=3600"
                                       }.AsImmutable
                                   ),
                        HTTPMethod.GET
                    );

            }

            else
                this.Log.Error(
                    $"No web interface to serve ({this.Frontend.Description}): the JSON API answers, the browser gets nothing. " +
                    "Build the frontend (npm run build in Frontend/) or point the CSMS at a directory with --frontend.",
                    "web"
                );

            #region Every request, into the log

            httpServer.OnHTTPRequest  += (server, request, cancellationToken) => {

                // The event stream is one request that stays open for as long
                // as a browser has the page open; logging it would say nothing
                // and logging its response would say it at the wrong moment.
                if (!IsEventStream(request))
                    this.Log.Debug($"{request.HTTPMethod} {request.Path} from {request.RemoteSocket}", "http");

                return Task.CompletedTask;

            };

            // Only OnHTTPResponse, and not OnHTTPError beside it: Hermod raises
            // both for the same response, and one line per request is what a
            // log is for.
            httpServer.OnHTTPResponse += (server, request, response, cancellationToken) => {

                if (IsEventStream(request))
                    return Task.CompletedTask;

                var code = response.HTTPStatusCode.Code;

                this.Log.Log(
                    code >= 500 ? LogLevel.Error
                        // A 401 is how the web interface asks whether anybody
                        // is signed in, and the answer "nobody" is not a fault.
                        : code == 401 ? LogLevel.Debug
                        : code >= 400 ? LogLevel.Warning
                        : LogLevel.Debug,
                    $"{code} {response.HTTPStatusCode.Name} for {request.HTTPMethod} {request.Path}",
                    "http"
                );

                return Task.CompletedTask;

            };

            #endregion

            #endregion

            #region The OCPP node

            csms01 = BuildOCPPNode(this.OCPP);

            // "this." and not for tidiness: the parameters of this constructor
            // shadow the properties of the same name, and the "Log" parameter
            // is null whenever the caller did not bring an event log of its own.
            this.Log.Info($"OCPP 2.1 CSMS '{csms01.Id}' is set up as {csms01.VendorName} {csms01.Model}.", "ocpp");

            #endregion

            #region The server the charging stations connect to

            // After the node, because it is attached to it, and after the
            // configuration file, because what it listens on is written there.
            // Nothing listens yet: Start() does.
            BuildOCPPServer(configuration?.OCPPServer);

            #endregion

        }

        #endregion


        #region Start()

        /// <summary>
        /// Start listening.
        /// </summary>
        public async Task Start()
        {

            if (started)
                return;

            await httpServer.Start();

            await StartOCPPServer();

            StartCheckingTheClock();

            started = true;

            Log.Notice($"The web interface is listening on {WebInterfaceURL}", "web", "http");
            Log.Info   ($"The JSON API is at {WebInterfaceURL}{httpRootPath.ToString().Trim('/')}/v1/status", "web", "http");

        }

        #endregion

        #region Stop()

        /// <summary>
        /// Stop listening.
        /// </summary>
        public async Task Stop()
        {

            if (!started)
                return;

            Log.Notice("The CSMS is shutting down.", "csms");

            timeCheckTimer?.Dispose();
            timeCheckTimer = null;

            // Before the server, and that order is the whole point: every
            // browser with the Logs page open holds a request that is waiting
            // for the next log entry rather than for its socket, and the HTTP
            // server waits for every request it started. Closing the sockets
            // does not wake those, so they are ended here first.
            API.CloseEventStreams();

            await StopOCPPServer();

            await httpServer.Stop();

            started = false;

        }

        #endregion

        #region ConfigurationJSON()

        /// <summary>
        /// What this CSMS is made of, as the Configuration page of
        /// the web interface reads it.
        /// </summary>
        /// <remarks>
        /// Read-only: it answers "what am I running", not "change it". Nothing
        /// here is a secret - the web login appears with its username and the
        /// path of its file, and never with anything about its password.
        /// </remarks>
        public JObject ConfigurationJSON()

            => new (

                   new JProperty("CSMS", new JObject(
                       new JProperty("version",        Version),
                       new JProperty("createdAt",      CreatedAt.ToString("o")),
                       new JProperty("machine",        Environment.MachineName),
                       new JProperty("runtime",        Environment.Version.ToString()),
                       new JProperty("os",             Environment.OSVersion.ToString())
                   )),

                   new JProperty("http",       new JObject(
                       new JProperty("serverName",     httpServer.HTTPServerName),
                       new JProperty("url",            WebInterfaceURL.ToString()),
                       new JProperty("apiPath",        httpRootPath.ToString()),
                       new JProperty("running",        started),
                       new JProperty("frontend",       Frontend.Description),
                       new JProperty("webInterface",   WebInterface is not null)
                   )),

                   new JProperty("web",        new JObject(
                       new JProperty("username",       Sessions.Username),
                       new JProperty("loginFile",      LoginFile.Path),
                       new JProperty("cookie",         Sessions.CookieName.ToString()),
                       new JProperty("secureCookies",  Sessions.SecureCookies),
                       new JProperty("idleTimeout",    Sessions.IdleTimeout.    ToString()),
                       new JProperty("maxLifetime",    Sessions.MaximumLifetime.ToString()),
                       new JProperty("sessions",       Sessions.Count)
                   )),

                   new JProperty("log",        new JObject(
                       new JProperty("capacity",       Log.Capacity),
                       new JProperty("entries",        Log.Count),
                       new JProperty("lastId",         Log.LastId),
                       new JProperty("debugBridge",    traceBridge is not null),
                       new JProperty("console",        consoleLog is not null),
                       new JProperty("tags",           new JArray(Log.KnownTags))
                   )),

                   new JProperty("time",       new JObject(
                       new JProperty("nts",            ntsClient.Hostname.ToString()),
                       new JProperty("now",            TimeProvider.GetUtcNow().ToString("o"))
                   )),

                   new JProperty("ocpp",       new JObject(
                       new JProperty("version",          "2.1"),
                       new JProperty("role",             "CSMS"),
                       new JProperty("id",               csms01.Id.ToString()),
                       new JProperty("vendor",           csms01.VendorName),
                       new JProperty("model",            csms01.Model),
                       new JProperty("serialNumber",     csms01.SerialNumber),
                       new JProperty("softwareVersion",  csms01.SoftwareVersion),
                       new JProperty("file",             ConfigFile.Path)
                   )),

                   new JProperty("stationServer", new JObject(
                       new JProperty("enabled",          OCPPServerEnabled),
                       new JProperty("running",          ocppServerStarted),
                       new JProperty("tls",              ocppServerTLS),
                       new JProperty("url",              OCPPServerURL),
                       new JProperty("securityProfiles", new JArray((ocppServerSettings.SecurityProfiles ?? []).Select(profile => (Int32) profile))),
                       new JProperty("stationLogins",    StationLogins.EnabledCount),
                       new JProperty("trustedChains",    ClientTrust.EnabledCount),
                       new JProperty("certificates",     ServerCertificates.Entries.Count)
                   )),

                   new JProperty("assemblies", new JArray(
                       AssemblyJSON<HTTPServer>                              ("Hermod"),
                       AssemblyJSON<NTSClient>                               ("Norn"),
                       AssemblyJSON<OCPPv2_1_CSMS.TestCSMSNode>     ("OCPP 2.1")
                   ))

               );

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
        /// beside the ones this class already made. One CSMS is one address to
        /// point a browser at - so the server and the HTTPExt API are made
        /// above, where the listening address, the port and the moment of
        /// starting are decided, and the node is handed a role rather than a
        /// socket.
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

                   DNSClient:                      dnsClient

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

        #region (private static) IsEventStream(Request)

        /// <summary>
        /// Whether this request is a browser hanging on the event stream.
        /// </summary>
        private static Boolean IsEventStream(HTTPRequest Request)
            => Request.Path.ToString().EndsWith("/events", StringComparison.Ordinal);

        #endregion

        #region DisposeAsync()

        /// <summary>
        /// Stop listening and let go of the console and the debug bridge.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            await Stop();

            traceBridge?.Dispose();
            consoleLog? .Dispose();

            ServerCertificates?.Dispose();
            ClientTrust?       .Dispose();

            reconfigureLock.Dispose();

            GC.SuppressFinalize(this);

        }

        #endregion

    }

}
