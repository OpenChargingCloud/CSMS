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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.CommandLine;
using cloud.charging.open.CSMS.OCPP;

using Node = cloud.charging.open.CSMS.Tests.KeyPinsOverOCPPTests.Controller;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// Who a request that comes in the overlay network is from: a frame of the overlay network names its
    /// network path itself - [2, destination, path, id, action, payload] - and a connection may speak only
    /// for itself, unless it is a local controller's, which speaks for the stations behind it; and the last
    /// hop of the path is always the node of the connection it came over.
    /// </summary>
    /// <remarks>
    /// What the CSMS does with a request in another station's name is what it does for that station: it
    /// enrols the SSH key a SignSSHKey brings as that station's - adding a login for a name it does not know -,
    /// and routes that station through whatever node a BootNotification names as its last hop. Each test
    /// sends as a node that dials the CSMS with a password of its own and says so, and looks at what came of
    /// it - not at an answer, which goes to the station named, by the CSMS's route to it.
    /// </remarks>
    public class OverlaySenderTests : ACSMSTests
    {

        #region Data

        private const String ThePassword = "a-password-long-enough-for-ocpp";

        private static readonly TimeSpan  Patience  = TimeSpan.FromSeconds(15);

        private readonly ConcurrentQueue<String>  said   = new ();
        private readonly List<Node>               nodes  = [];

        #endregion

        #region (override) Configuration

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

        [SetUp]
        public void Listen()
        {
            said.Clear();
            CSMS.Log.OnLogged += entry => said.Enqueue(entry.Message);
        }

        [TearDown]
        public async Task HangUp()
        {

            foreach (var node in nodes)
                await node.DisposeAsync();

            nodes.Clear();

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// A node that dials the CSMS under its own login, with its password, in the overlay network or not.
        /// </summary>
        private async Task<Node> Dialling(String   Id,
                                          Boolean  Overlay   = true)
        {

            Assert.That(CSMS.StationLogins.TrySetPassword(Id, ThePassword, null, null, out _, out var error), Is.True, error);

            var node = await Node.Connect(CSMS.OCPPServerSettings.TCPPort!.Value.ToUInt16(), ThePassword, Id, Overlay);

            nodes.Add(node);

            await Until(() => CSMS.IsConnected(Id), $"'{Id}' counting as connected");

            return node;

        }

        private static JObject SignSSHKey(String PublicKey)

            => new (
                   new JProperty("purpose",    "OCPP"),
                   new JProperty("publicKey",  PublicKey)
               );

        private static JObject ABootNotification()

            => new (
                   new JProperty("chargingStation", new JObject(
                       new JProperty("model",       "Bay"),
                       new JProperty("vendorName",  "GraphDefined")
                   )),
                   new JProperty("reason", "PowerUp")
               );

        private static String AnSSHKey()
            => SshPublicKey.FromHostKey(SshHostKey.GenerateEd25519()).ToAuthorizedKeyLine();

        /// <summary>
        /// How many SSH keys the CSMS lets the given station sign in with; none where it has no such login.
        /// </summary>
        private Int32 KeysOf(String Station)

            => CSMS.StationLogins.Logins.FirstOrDefault(login => login.Id == Station)?.Keys.Count ?? 0;

        private Boolean HasALogin(String Station)
            => CSMS.StationLogins.Logins.Any(login => login.Id == Station);

        /// <summary>
        /// The node the CSMS routes the given station through, where it has a route.
        /// </summary>
        private String? RouteOf(String Station)

            => CSMS.Node.Routing.LookupNetworkingNode(NetworkingNode_Id.Parse(Station), out var reachability)
                   ? reachability?.NetworkingHub?.ToString() ?? reachability?.DestinationId.ToString()
                   : null;

        private Boolean Said(String Text)
            => said.Any(line => line.Contains(Text, StringComparison.Ordinal));

        private String Log
            => String.Join(Environment.NewLine, said);

        private static async Task Until(Func<Boolean> Condition, String What)
        {

            var giveUp = DateTimeOffset.UtcNow + Patience;

            while (!Condition() && DateTimeOffset.UtcNow < giveUp)
                await Task.Delay(20);

            Assert.That(Condition(), Is.True, $"Waited in vain for {What}.");

        }

        #endregion


        #region AStation_CannotHaveAnSSHKeyEnrolled_InAnotherStationsName()

        /// <summary>
        /// A station in the overlay network sends SignSSHKey under the network path of another station: the
        /// key is not enrolled for that station - it would sign in as it from then on.
        /// </summary>
        [Test]
        public async Task AStation_CannotHaveAnSSHKeyEnrolled_InAnotherStationsName()
        {

            Assert.That(CSMS.StationLogins.TrySetPassword("cs001", ThePassword, null, null, out _, out var error), Is.True, error);

            var impostor  = await Dialling("cs009");
            var key       = AnSSHKey();

            await impostor.TellAs(new JArray("cs001"), "SignSSHKey", SignSSHKey(key));

            await Until(() => KeysOf("cs001") > 0 || Said("in the name of 'cs001'"), "the key enrolled, or the CSMS saying it is not");

            // Whatever was under way, given its time.
            await Task.Delay(300);

            Assert.That(KeysOf("cs001"), Is.Zero, $"the impostor's key lets it in as 'cs001'.{Environment.NewLine}{Log}");

        }

        #endregion

        #region AStation_CannotHaveALoginMade_InANameNobodyHas()

        /// <summary>
        /// The same for a name the CSMS has no login of: none is made, with the impostor's key.
        /// </summary>
        [Test]
        public async Task AStation_CannotHaveALoginMade_InANameNobodyHas()
        {

            var impostor = await Dialling("cs009");

            await impostor.TellAs(new JArray("cs777"), "SignSSHKey", SignSSHKey(AnSSHKey()));

            await Until(() => HasALogin("cs777") || Said("in the name of 'cs777'"), "a login made, or the CSMS saying it is not");

            await Task.Delay(300);

            Assert.That(HasALogin("cs777"), Is.False, $"a login was made for the impostor's key.{Environment.NewLine}{Log}");

        }

        #endregion

        #region AStation_CannotNameItselfTheWayToAnotherStation()

        /// <summary>
        /// A station that is no local controller sends a BootNotification of another station, naming itself
        /// the last hop - as a controller forwards one: the CSMS does not route that station through it, and
        /// notes it behind no controller.
        /// </summary>
        [Test]
        public async Task AStation_CannotNameItselfTheWayToAnotherStation()
        {

            var impostor = await Dialling("cs009");

            await impostor.TellAs(new JArray("cs001", "cs009"), "BootNotification", ABootNotification());

            await Until(() => RouteOf("cs001") is not null || Said("in the name of 'cs001'"), "a route to 'cs001', or the CSMS saying there is none");

            await Task.Delay(300);

            Assert.Multiple(() => {
                Assert.That(RouteOf("cs001"),                        Is.Null, $"'cs001' is routed through the impostor.{Environment.NewLine}{Log}");
                Assert.That(CSMS.KeyPins.LocalControllerOf("cs001"), Is.Null, "'cs001' is noted behind the impostor");
            });

        }

        #endregion

        #region ANode_CannotNameAnotherAsTheLastHop()

        /// <summary>
        /// A frame whose network path ends in another node than the one whose connection it came over: the
        /// last hop is the connection's node, whatever the frame says.
        /// </summary>
        [Test]
        public async Task ANode_CannotNameAnotherAsTheLastHop()
        {

            var impostor = await Dialling("cs009");

            await impostor.TellAs(new JArray("cs001", "lc001"), "BootNotification", ABootNotification());

            await Until(() => RouteOf("cs001") is not null || Said("'lc001'"), "a route to 'cs001', or the CSMS saying there is none");

            await Task.Delay(300);

            Assert.Multiple(() => {
                Assert.That(RouteOf("cs001"),                        Is.Null, $"'cs001' is routed through the node the frame named.{Environment.NewLine}{Log}");
                Assert.That(CSMS.KeyPins.LocalControllerOf("cs001"), Is.Null, "'cs001' is noted behind the node the frame named");
            });

        }

        #endregion

        #region AStation_StillSpeaksForItself_InTheOverlayNetwork()

        /// <summary>
        /// What a station sends in its own name in the overlay network is answered. (In standard mode a frame
        /// names no path: the CSMS puts the connection's node in, as it always did.)
        /// </summary>
        [Test]
        public async Task AStation_StillSpeaksForItself_InTheOverlayNetwork()
        {

            var station  = await Dialling("cs009");

            var boot     = await station.AskAs(new JArray("cs009"), "BootNotification", ABootNotification(), Patience);

            Assert.That(boot?.Last?["status"]?.Value<String>(), Is.EqualTo("Accepted"), $"{boot}{Environment.NewLine}{Log}");

        }

        #endregion


        #region (private) AController(Id) / AnAccount(Name, Role) / OverSSHAs(Name, Role) / Run(CLI, CommandLine)

        /// <summary>
        /// A local controller in the overlay network, its login marked as one.
        /// </summary>
        private async Task<Node> AController(String Id)
        {

            var controller = await Dialling(Id);

            Assert.That(CSMS.StationLogins.TrySetLocalController(Id, true, out var error), Is.True, error);

            return controller;

        }

        /// <summary>
        /// An account of the given name in the group of the given role, and its password.
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

        private CSMSCLI OverSSHAs(IUser Account)

            => new (CSMS,
                    new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask),
                    new CLICaller(Account, null!));

        private static async Task<String> Run(CSMSCLI  CLI,
                                              String   CommandLine)
        {

            var lines = String.Join(Environment.NewLine, await CLI.Execute(CommandLine));

            TestContext.Out.WriteLine($"> {CommandLine}");
            TestContext.Out.WriteLine(lines);

            return lines;

        }

        #endregion


        #region ALocalController_SpeaksForTheStationsBehindIt()

        /// <summary>
        /// A local controller, its login marked as one, sends a BootNotification of a station behind it: the CSMS
        /// takes it, routes the station through the controller, and its answer reaches the controller.
        /// </summary>
        [Test]
        public async Task ALocalController_SpeaksForTheStationsBehindIt()
        {

            var controller  = await AController("lc001");

            var boot        = await controller.AskAs(new JArray("cs001", "lc001"), "BootNotification", ABootNotification(), Patience);

            Assert.Multiple(() => {
                Assert.That(boot?.Last?["status"]?.Value<String>(), Is.EqualTo("Accepted"), $"{boot}{Environment.NewLine}{Log}");
                Assert.That(RouteOf("cs001"),                       Is.EqualTo("lc001"));
                Assert.That(Said("and it is dropped"),              Is.False, Log);
            });

        }

        #endregion

        #region ALocalController_TooIsTheLastHopOfWhatItSends()

        /// <summary>
        /// A local controller, too, is the last hop of whatever it sends: a path that ends in another node is
        /// dropped.
        /// </summary>
        [Test]
        public async Task ALocalController_TooIsTheLastHopOfWhatItSends()
        {

            var controller = await AController("lc001");

            await controller.TellAs(new JArray("cs001", "lc002"), "BootNotification", ABootNotification());

            await Until(() => RouteOf("cs001") is not null || Said("'lc002'"), "a route to 'cs001', or the CSMS saying there is none");

            await Task.Delay(300);

            Assert.Multiple(() => {
                Assert.That(RouteOf("cs001"),  Is.Null, Log);
                Assert.That(Log,               Does.Contain("ends in 'lc002', but it came over the connection of 'lc001'"));
            });

        }

        #endregion

        #region AnUnmarkedController_IsDropped_AndTheLogSaysHowToMarkIt()

        /// <summary>
        /// A local controller whose login nobody marked is a station to the CSMS: what it forwards is dropped,
        /// and the log says how to mark it.
        /// </summary>
        [Test]
        public async Task AnUnmarkedController_IsDropped_AndTheLogSaysHowToMarkIt()
        {

            var controller = await Dialling("lc001");

            await controller.TellAs(new JArray("cs001", "lc001"), "BootNotification", ABootNotification());

            await Until(() => RouteOf("cs001") is not null || Said("in the name of 'cs001'"), "a route to 'cs001', or the CSMS saying there is none");

            Assert.Multiple(() => {
                Assert.That(RouteOf("cs001"),  Is.Null, Log);
                Assert.That(Log,               Does.Contain("'localControllers lc001 on'"));
            });

        }

        #endregion

        #region TheMark_IsSetAtTheConsole_AndByTheAPI_AtTheStationsEditing()

        /// <summary>
        /// A login is marked as a local controller's and unmarked at the console and by the API - not by an
        /// account that may only look at the stations - and the mark is written down with the login.
        /// </summary>
        [Test]
        public async Task TheMark_IsSetAtTheConsole_AndByTheAPI_AtTheStationsEditing()
        {

            Assert.That(CSMS.StationLogins.TrySetPassword("lc001", ThePassword, null, null, out _, out var error), Is.True, error);

            var (vera, veraPassword) = await AnAccount("vera", "viewer");

            using var console   = new CSMSCLI(CSMS);
            using var viewer    = OverSSHAs(vera);

            var viewerMarks     = await Run(viewer,  "localControllers lc001 on");
            var unmarked        = CSMS.StationLogins.IsLocalController("lc001");
            var marked          = await Run(console, "localControllers lc001 on");
            var listed          = await Run(console, "localControllers");
            var nobody          = await Run(console, "localControllers cs404 on");
            var written         = ChargingStationLogin.TryParse(CSMS.StationLogins.Logins.Single(login => login.Id == "lc001").ToJSON(WithSecrets: true), out var reread, out var parseError);
            var unmarking       = await Run(console, "localControllers lc001 off");
            var afterConsole    = CSMS.StationLogins.IsLocalController("lc001");

            var admin           = await SignedIn();
            var viewerHTTP      = await SignedInAs("vera", veraPassword);

            var viewerPut       = await viewerHTTP.PutAsync("api/v1/configuration/ocpp-server/stations/lc001", JSONBody(new JProperty("localController", true)));
            var notABoolean     = await admin.     PutAsync("api/v1/configuration/ocpp-server/stations/lc001", JSONBody(new JProperty("localController", "yes")));
            var adminPut        = await admin.     PutAsync("api/v1/configuration/ocpp-server/stations/lc001", JSONBody(new JProperty("localController", true)));
            var listing         = await GetJSON(admin, "api/v1/configuration/ocpp-server/stations");

            Assert.Multiple(() => {

                Assert.That(viewerMarks,                    Does.Contain("may not do that here"));
                Assert.That(unmarked,                       Is.False, "a viewer marked the login");
                Assert.That(marked,                         Does.Contain("is a local controller now"));
                Assert.That(listed,                         Does.Contain("lc001"));
                Assert.That(nobody,                         Does.Contain("never heard of"));
                Assert.That(written,                        Is.True, parseError);
                Assert.That(reread?.LocalController,        Is.True, "the mark is not written down with the login");
                Assert.That(unmarking,                      Does.Contain("no local controller any more"));
                Assert.That(afterConsole,                   Is.False);

                Assert.That(viewerPut.StatusCode,           Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(notABoolean.StatusCode,         Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(adminPut.StatusCode,            Is.EqualTo(HttpStatusCode.OK));
                Assert.That(CSMS.StationLogins.IsLocalController("lc001"), Is.True);
                Assert.That((listing["stations"] as JArray)?.OfType<JObject>().
                                Single(station => station.Value<String>("id") == "lc001").
                                Value<Boolean>("localController"),
                                                            Is.True, listing.ToString());

            });

        }

        #endregion

    }

}
