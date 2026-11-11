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
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;

using cloud.charging.open.CSMS.CommandLine;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The OCPP library's operator commands at the command line of a CSMS:
    /// sent to the charging station chosen with 'use', and only by somebody
    /// who may run the stations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reset stands for all of them: what each sends is the OCPP library's,
    /// and tested there. What is tested here is what the CSMS puts around
    /// them - which station they go to, who may send them, and that they are
    /// not offered before there is a station to send them to.
    /// </para>
    /// <para>
    /// An account over SSH is a caller with the account and no session: the
    /// rechecks of a session are the node's, and tested there. What is tested
    /// here is the role.
    /// </para>
    /// </remarks>
    public class StationOperationTests : AConnectedStationTests
    {

        #region (private) Console()

        /// <summary>
        /// The command line of this CSMS's own console.
        /// </summary>
        private CSMSCLI Console()
            => new (CSMS);

        #endregion

        #region (private) OverSSHAs(Name, Role)

        /// <summary>
        /// The command line an account of the given name and role gets over
        /// SSH - made for the purpose, as the CSMS makes its first one.
        /// </summary>
        private async Task<CSMSCLI> OverSSHAs(String  Name,
                                              String  Role)
        {

            Assert.That(CSMS.ExtAPI.TryGetOrganization(Organization_Id.Parse(CSMS.DefaultOrganization), out var organization) &&
                        organization is Organization, Is.True, "the CSMS's organization is not there");

            await CSMS.ExtAPI.CreateUser(
                      User_Id.Parse(Name),
                      I18NString.Create(Languages.en, Name),
                      SimpleEMailAddress.Parse($"{Name}@localhost"),
                      User2OrganizationEdgeLabel.IsMember,
                      (Organization) organization!,
                      Password:                  "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8],
                      SkipDefaultNotifications:  true,
                      SkipNewUserEMail:          true,
                      SkipNewUserNotifications:  true,
                      AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                      IsAuthenticated:           true
                  );

            Assert.That(CSMS.ExtAPI.TryGetUser     (User_Id.     Parse(Name), out var account), Is.True, $"the account '{Name}' was not made");
            Assert.That(CSMS.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group),   Is.True, $"the CSMS has no group '{Role}'");

            var joined = await CSMS.ExtAPI.AddUserToUserGroup((User) account!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            Assert.That(joined.IsSuccess, Is.True, $"'{Name}' could not be put in '{Role}'");

            return new CSMSCLI(CSMS,
                               new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask),
                               new CLICaller(account!, null!));

        }

        #endregion

        #region (private static) Run(CLI, CommandLine)

        private static async Task<String[]> Run(CSMSCLI  CLI,
                                                String   CommandLine)
        {

            var lines = await CLI.Execute(CommandLine);

            TestContext.Out.WriteLine($"> {CommandLine}");
            TestContext.Out.WriteLine(String.Join(Environment.NewLine, lines));

            return lines;

        }

        #endregion

        #region (private) ResetAccepted()

        /// <summary>
        /// A station that takes a reset.
        /// </summary>
        private void ResetAccepted()

            => OnCall = (action, payload, n) => action == "Reset"
                            ? [ Accepted ]
                            : [];

        #endregion


        #region TheOCPPCommandsAreNotOfferedBeforeAStationIsInUse()

        /// <summary>
        /// Without a station chosen, an OCPP command would not know where to
        /// go, and is not there at all.
        /// </summary>
        [Test]
        public async Task TheOCPPCommandsAreNotOfferedBeforeAStationIsInUse()
        {

            using var cli = Console();

            Assert.That(await Run(cli, "reset immediate"), Is.EqualTo(new[] { "Unknown command: reset" }));
            Assert.That(Calls, Is.Empty);

        }

        #endregion

        #region AnOCPPCommandGoesToTheStationInUse()

        /// <summary>
        /// 'use' chooses the station, and reset is sent to it - and what it
        /// answered is written.
        /// </summary>
        [Test]
        public async Task AnOCPPCommandGoesToTheStationInUse()
        {

            ResetAccepted();

            using var cli = Console();

            Assert.That((await Run(cli, "use cs001")).Single(), Is.EqualTo("Using the charging station 'cs001': the OCPP commands go to it."));

            var lines = await Run(cli, "reset immediate");

            Assert.Multiple(() => {
                Assert.That(lines.First(),                              Does.StartWith("reset immediate => "));
                Assert.That(String.Join(" ", lines),                    Does.Contain("Accepted"));
                Assert.That(Calls.Single()[2]!.Value<String>(),         Is.EqualTo("Reset"));
                Assert.That(Calls.Single()[3]!["type"]!.Value<String>(), Is.EqualTo("Immediate"));
            });

        }

        #endregion

        #region UseSaysWhichStationIsInUse_AndADashChoosesNone()

        [Test]
        public async Task UseSaysWhichStationIsInUse_AndADashChoosesNone()
        {

            using var cli = Console();

            Assert.That((await Run(cli, "use")).Single(),        Does.StartWith("No charging station is in use"));
            Assert.That((await Run(cli, "use cs001")).Single(),  Does.StartWith("Using the charging station 'cs001'"));
            Assert.That((await Run(cli, "use")).Single(),        Does.StartWith("Using the charging station 'cs001'"));
            Assert.That((await Run(cli, "use -")).Single(),      Is.EqualTo("No charging station is in use any more."));
            Assert.That((await Run(cli, "reset immediate")),     Is.EqualTo(new[] { "Unknown command: reset" }));

        }

        #endregion

        #region AStationThatIsNotConnectedCannotBeUsed()

        [Test]
        public async Task AStationThatIsNotConnectedCannotBeUsed()
        {

            using var cli = Console();

            Assert.That((await Run(cli, "use cs404")).Single(),  Is.EqualTo("The charging station 'cs404' is not connected."));
            Assert.That((await Run(cli, "use")).Single(),        Does.StartWith("No charging station is in use"));

        }

        #endregion

        #region AViewerMayLookAtTheConnections_ButNeitherChooseAStationNorSendToOne()

        /// <summary>
        /// A viewer is told no at 'use' - and, where the station was set by
        /// hand with setEnv instead, at the command itself: nothing reaches the
        /// station either way.
        /// </summary>
        [Test]
        public async Task AViewerMayLookAtTheConnections_ButNeitherChooseAStationNorSendToOne()
        {

            ResetAccepted();

            using var cli = await OverSSHAs("vera", "viewer");

            Assert.That(String.Join(" | ", await Run(cli, "connections")),   Does.Contain("cs001"));
            Assert.That((await Run(cli, "use cs001")).Single(),              Does.Contain("'vera' may not do that here"));

            await Run(cli, "setEnv remoteSystemId cs001");
            await Run(cli, "setEnv remoteSystemOCPPVersion OCPPv2.1");

            Assert.That((await Run(cli, "reset immediate")).Single(),        Does.Contain("'vera' may not do that here"));
            Assert.That(Calls, Is.Empty, "a viewer's reset reached the station");

        }

        #endregion

        #region ACPOMayRunTheStations()

        [Test]
        public async Task ACPOMayRunTheStations()
        {

            ResetAccepted();

            using var cli = await OverSSHAs("carl", "cpo");

            Assert.That((await Run(cli, "use cs001")).Single(),  Does.StartWith("Using the charging station 'cs001'"));
            Assert.That((await Run(cli, "reset immediate")).First(), Does.StartWith("reset immediate => "));
            Assert.That(Calls.Single()[2]!.Value<String>(),     Is.EqualTo("Reset"));

        }

        #endregion

        #region TheLibrarysQueryDNSIsLeftOut_ForTheNodesOwn()

        /// <summary>
        /// The OCPP library has a queryDNS of its own, which would take the
        /// node's away as soon as a station is in use: two commands of one
        /// name are no command. The CSMS's stationQueryDNS is the library's.
        /// </summary>
        [Test]
        public async Task TheLibrarysQueryDNSIsLeftOut_ForTheNodesOwn()
        {

            using var cli = Console();

            await Run(cli, "use cs001");

            Assert.That(String.Join(" | ", await Run(cli, "queryDNS")), Does.Not.StartWith("Unknown command"));
            Assert.That(cli.Commands.OfType<StationOperation>().Select(operation => operation.CommandName), Does.Not.Contain("queryDNS"));
            Assert.That(cli.Commands.OfType<StationOperation>().Select(operation => operation.CommandName), Does.Contain("reset"));

        }

        #endregion

        #region ConnectionsSaysFromWhereAndHowMuch()

        [Test]
        public async Task ConnectionsSaysFromWhereAndHowMuch()
        {

            using var cli = Console();

            var lines = await Run(cli, "connections");

            Assert.That(lines.First(),  Is.EqualTo("1 charging station connection(s):"));
            Assert.That(lines[1],       Does.Match(@"^  cs001  from 127\.0\.0\.1:\d+, frames in/out \d+/\d+, last in .+, last out .+$"));

        }

        #endregion

    }

}
