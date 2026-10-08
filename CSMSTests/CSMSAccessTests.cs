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

using System.Net;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// Who may do what on a CSMS: its three resources beside the node's, its
    /// CPO beside the node's viewer and administrators - and a role from the
    /// configuration file, heard by the API like every other.
    /// </summary>
    public class CSMSAccessTests
    {

        #region Data

        private String            directory   = "";
        private CSMS?             csms;
        private Uri?              address;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
        {
            directory = TestCSMSs.TemporaryDirectory("access");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task TakeItAwayAgain()
        {

            if (csms is not null)
                await csms.DisposeAsync();

            csms = null;

            TestCSMSs.Remove(directory);

        }

        #endregion


        #region (private) ACSMS(Configuration = null)

        /// <summary>
        /// A CSMS with the given configuration file, off the network: made, and
        /// not yet started.
        /// </summary>
        private CSMS ACSMS(JObject? Configuration = null)
        {

            csms     = TestCSMSs.New(directory, Configuration ?? TestCSMSs.Offline);
            address  = new Uri(csms.WebInterfaceURL.ToString());

            return csms;

        }

        #endregion

        #region (private) AStartedCSMS(Configuration = null)

        /// <summary>
        /// A CSMS as ACSMS makes it, started - and made again, on fresh ports,
        /// where another test run on this machine took one before the CSMS
        /// could bind it.
        /// </summary>
        private Task<CSMS> AStartedCSMS(JObject? Configuration = null)

            => TestPorts.StartedOnFreshPorts(() => ACSMS(Configuration));

        #endregion

        #region (private) SignedInAs(Name, Role)

        /// <summary>
        /// A browser signed in with a password as an account of the given name,
        /// made for the purpose and put in the group of the given role, or in
        /// none - made the way the CSMS makes its first one, so that it
        /// may sign in.
        /// </summary>
        private async Task<HttpClient> SignedInAs(String   Name,
                                                  String?  Role)
        {

            var password = "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8];

            Assert.That(csms!.ExtAPI.TryGetOrganization(Organization_Id.Parse(CSMS.DefaultOrganization), out var organization) &&
                        organization is Organization, Is.True, "the CSMS's organization is not there");

            var account = await csms.ExtAPI.CreateUser(
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

            Assert.That(account,                                                          Is.Not.Null, $"the account '{Name}' was not made");
            Assert.That(csms.ExtAPI.TryGetUser(User_Id.Parse(Name), out var stored),  Is.True);

            if (Role is not null)
            {

                Assert.That(csms.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group), Is.True,
                            $"the CSMS has no group '{Role}'");

                var joined = await csms.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

                Assert.That(joined.IsSuccess, Is.True, $"'{Name}' could not be put in '{Role}'");

            }

            // Signed in the way a browser is, at the HTTPExt API, and carrying
            // the session cookie from there on: one password check rather than
            // one per request.
            var client   = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer(), UseCookies = true }) {
                               BaseAddress  = address,
                               Timeout      = TimeSpan.FromSeconds(30)
                           };

            var signedIn = await client.PostAsync($"{CSMS.ExtAPIPath.ToString().TrimEnd('/')}/login",
                                                  new FormUrlEncodedContent([
                                                      new KeyValuePair<String, String>("login",     Name),
                                                      new KeyValuePair<String, String>("password",  password)
                                                  ]));

            Assert.That(signedIn.IsSuccessStatusCode, Is.True, $"'{Name}' could not sign in: {(Int32) signedIn.StatusCode}");

            return client;

        }

        #endregion

        #region (private static) Post(Client, Path, JSON)

        private static Task<HttpResponseMessage> Post(HttpClient  Client,
                                                      String      Path,
                                                      String      JSON)

            => Client.PostAsync(Path, new StringContent(JSON, Encoding.UTF8, "application/json"));

        #endregion

        #region (private static) CSMSAccessControl()

        /// <summary>
        /// The CSMS's resources and roles, as a node told nothing else puts
        /// them together.
        /// </summary>
        private static AccessControl CSMSAccessControl()
        {

            Assert.That(AccessControl.TryCombine(CSMSAccess.Resources, CSMSAccess.Roles, null, null,
                                                 "CSMS", out var access, out _, out var error),
                        Is.True, error);

            return access!;

        }

        #endregion


        #region ACSMSKnowsItsResourcesAndItsThreeRoles()

        /// <summary>
        /// The node brings the viewer and the administrators, and the CSMS its
        /// CPO - and the charging stations, the locations and the roaming as
        /// resources beside the node's.
        /// </summary>
        [Test]
        public void ACSMSKnowsItsResourcesAndItsThreeRoles()
        {

            var cs = ACSMS();

            Assert.Multiple(() => {
                Assert.That(cs.Roles,             Is.EqualTo(new[] { "viewer", "cpo", WWCPNode.AdminRole }));
                Assert.That(cs.Access.Resources,  Is.EqualTo(new[] { "configuration", "dns", "nts", "certificates", "stations", "locations", "roaming" }));
            });

        }

        #endregion

        #region EachRoleMayDoWhatItAlwaysMayDo(Role, Permission, Allowed)

        /// <summary>
        /// What each role could do before roles were data, permission by
        /// permission: the viewer looks, the CPO runs the charging stations -
        /// their name and time servers, the stations and their locations - and
        /// only the administrators touch the certificates and the roaming.
        /// </summary>
        [TestCase("viewer",       "configuration:read",  true)]
        [TestCase("viewer",       "dns:read",            true)]
        [TestCase("viewer",       "stations:read",       true)]
        [TestCase("viewer",       "locations:read",      true)]
        [TestCase("viewer",       "roaming:read",        true)]
        [TestCase("viewer",       "certificates:read",   true)]
        [TestCase("viewer",       "dns:edit",            false)]
        [TestCase("viewer",       "dns:run",             false)]
        [TestCase("viewer",       "stations:edit",       false)]
        [TestCase("viewer",       "locations:edit",      false)]
        [TestCase("viewer",       "roaming:edit",        false)]
        [TestCase("viewer",       "certificates:edit",   false)]

        [TestCase("cpo",          "certificates:read",   true)]
        [TestCase("cpo",          "roaming:read",        true)]
        [TestCase("cpo",          "dns:edit",            true)]
        [TestCase("cpo",          "dns:run",             true)]
        [TestCase("cpo",          "nts:edit",            true)]
        [TestCase("cpo",          "nts:run",             true)]
        [TestCase("cpo",          "stations:edit",       true)]
        [TestCase("cpo",          "locations:edit",      true)]
        [TestCase("cpo",          "roaming:edit",        false)]
        [TestCase("cpo",          "certificates:edit",   false)]
        [TestCase("cpo",          "configuration:edit",  false)]

        [TestCase("systemadmin",  "certificates:edit",   true)]
        [TestCase("systemadmin",  "roaming:edit",        true)]
        [TestCase("systemadmin",  "stations:edit",       true)]
        [TestCase("systemadmin",  "locations:edit",      true)]
        public void EachRoleMayDoWhatItAlwaysMayDo(String Role, String Permission, Boolean Allowed)
        {

            Assert.That(protocols.WWCP.Node.Web.Permission.TryParse(Permission, out var permission, out var error), Is.True, error);

            Assert.That(CSMSAccessControl().RoleNamed(Role)!.Allows(permission.Resource, permission.Operation), Is.EqualTo(Allowed));

        }

        #endregion


        #region ACPOMayLookAtTheCertificatesAndIsToldWhoMayChangeThem()

        /// <summary>
        /// Over the wire, as a browser signed in as a CPO sees it: the page
        /// opens, a signing request is refused with the role to ask for, and
        /// what the browser is told it may do says the same beforehand.
        /// </summary>
        [Test]
        public async Task ACPOMayLookAtTheCertificatesAndIsToldWhoMayChangeThem()
        {

            await AStartedCSMS();

            using var cpo    = await SignedInAs("cpo1", "cpo");

            var looked       = await cpo.GetAsync("api/v1/configuration/ocpp-server/certificates");
            var requested    = await Post(cpo, "api/v1/configuration/ocpp-server/certificates", "{}");
            var refusal      = await requested.Content.ReadAsStringAsync();
            var me           = JObject.Parse(await (await cpo.GetAsync("api/v1/auth/me")).Content.ReadAsStringAsync());
            var permissions  = me["permissions"]!.Values<String>().OfType<String>().ToArray();

            Assert.Multiple(() => {
                Assert.That(looked.StatusCode,               Is.EqualTo(HttpStatusCode.OK));
                Assert.That(requested.StatusCode,            Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(refusal,                         Does.Contain("This needs the systemadmin role."));
                Assert.That(me["roles"]!.Values<String>(),   Is.EqualTo(new[] { "cpo" }));
                Assert.That(permissions,                     Does.Contain("stations:edit").And.Contain("locations:edit").And.Contain("dns:run").And.Contain("certificates:read"));
                Assert.That(permissions,                     Does.Not.Contain("certificates:edit").And.Not.Contain("roaming:edit").And.Not.Contain("configuration:edit"));
                Assert.That(permissions.Any(permission => permission.StartsWith('*')),
                            Is.False,
                            "spelt out resource by resource, so that a page asking \"dns:read\" need not know what \"*\" is");
            });

        }

        #endregion

        #region ARoleFromTheConfigurationFileIsHeardByTheAPI()

        /// <summary>
        /// A role nobody compiled in: the file names it - with a resource of
        /// the CSMS's own beside one of the node's - the start makes its group,
        /// and a route asking for a permission lets it in or not by what the
        /// file says it carries.
        /// </summary>
        [Test]
        public async Task ARoleFromTheConfigurationFileIsHeardByTheAPI()
        {

            await AStartedCSMS(new JObject(
                                   new JProperty("nts",    new JObject(new JProperty("enabled", false))),
                                   new JProperty("roles",  new JObject(
                                       new JProperty("support", new JArray("dns:read", "stations:read"))
                                   ))
                               ));

            using var support  = await SignedInAs("supporter", "support");

            var dns            = await support.GetAsync("api/v1/configuration/dns");
            var stations       = await support.GetAsync("api/v1/configuration/ocpp-server/stations");
            var partners       = await support.GetAsync("api/v1/ocpi/partners");
            var refusal        = await partners.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(csms!.Roles,          Is.EqualTo(new[] { "viewer", "cpo", "support", WWCPNode.AdminRole }));
                Assert.That(dns.StatusCode,       Is.EqualTo(HttpStatusCode.OK));
                Assert.That(stations.StatusCode,  Is.EqualTo(HttpStatusCode.OK));
                Assert.That(partners.StatusCode,  Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(refusal,              Does.Contain("This needs the viewer or cpo or systemadmin role."),
                            "the file's role carries dns:read and stations:read and nothing else, so it is not among the ones to ask for");
            });

        }

        #endregion

        #region ARoleNamingAResourceThisCSMSDoesNotHaveStopsTheStart()

        /// <summary>
        /// A role in the file that names a resource the CSMS does not have - a
        /// vehicle's, say - stops it being built, and says which resources it
        /// does have: the node's, and the three it hands in.
        /// </summary>
        [Test]
        public void ARoleNamingAResourceThisCSMSDoesNotHaveStopsTheStart()
        {

            var refused = Assert.Throws<InvalidOperationException>(() => ACSMS(new JObject(
                              new JProperty("nts",    new JObject(new JProperty("enabled", false))),
                              new JProperty("roles",  new JObject(
                                  new JProperty("support", new JArray("vehicle:read"))
                              ))
                          )));

            Assert.That(refused!.Message, Does.Contain("'vehicle'").And.Contain("stations").And.Contain("locations").And.Contain("roaming"));

        }

        #endregion

        #region EveryRouteAsksForItsOwnPermission(Method, Path, Permission)

        /// <summary>
        /// Every route of the API, and the one permission it asks for - read
        /// off the refusal an account in no role at all is given, which names
        /// every role that may. The configuration file adds a role for each
        /// operation on each resource, "r-dns-edit" and so on, so that the
        /// refusal names exactly one of them: the permission the route asks.
        /// </summary>
        /// <remarks>
        /// Refusals only: an account in no role is turned away before anything
        /// is read, so a route that would synchronise the clock or remove a
        /// certificate does neither here.
        /// </remarks>
        [TestCase("GET",     "api/v1/configuration",                                      "configuration:read")]
        [TestCase("GET",     "api/v1/configuration/dns",                                  "dns:read")]
        [TestCase("PUT",     "api/v1/configuration/dns",                                  "dns:edit")]
        [TestCase("POST",    "api/v1/configuration/dns/query",                            "dns:run")]
        [TestCase("GET",     "api/v1/configuration/nts",                                  "nts:read")]
        [TestCase("PUT",     "api/v1/configuration/nts",                                  "nts:edit")]
        [TestCase("POST",    "api/v1/configuration/nts/sync",                             "nts:run")]
        [TestCase("POST",    "api/v1/configuration/nts/test",                             "nts:run")]
        [TestCase("GET",     "api/v1/configuration/ocpp-server",                          "stations:read")]
        [TestCase("PUT",     "api/v1/configuration/ocpp-server",                          "stations:edit")]
        [TestCase("GET",     "api/v1/configuration/ocpp-server/stations",                 "stations:read")]
        [TestCase("POST",    "api/v1/configuration/ocpp-server/stations",                 "stations:edit")]
        [TestCase("PUT",     "api/v1/configuration/ocpp-server/stations/cs001",           "stations:edit")]
        [TestCase("DELETE",  "api/v1/configuration/ocpp-server/stations/cs001",           "stations:edit")]
        [TestCase("PUT",     "api/v1/configuration/ocpp-server/stations/cs001/totp",      "stations:edit")]
        [TestCase("DELETE",  "api/v1/configuration/ocpp-server/stations/cs001/totp",      "stations:edit")]
        [TestCase("DELETE",  "api/v1/configuration/ocpp-server/stations/cs001/password",  "stations:edit")]
        [TestCase("POST",    "api/v1/configuration/ocpp-server/groups",                   "stations:edit")]
        [TestCase("PUT",     "api/v1/configuration/ocpp-server/groups/site",              "stations:edit")]
        [TestCase("DELETE",  "api/v1/configuration/ocpp-server/groups/site",              "stations:edit")]
        [TestCase("GET",     "api/v1/configuration/ocpp-server/certificates",             "certificates:read")]
        [TestCase("POST",    "api/v1/configuration/ocpp-server/certificates",             "certificates:edit")]
        [TestCase("POST",    "api/v1/configuration/ocpp-server/certificates/inspect",     "certificates:edit")]
        [TestCase("POST",    "api/v1/configuration/ocpp-server/certificates/upload",      "certificates:edit")]
        [TestCase("GET",     "api/v1/configuration/ocpp-server/certificates/k1/csr",      "certificates:read")]
        [TestCase("PUT",     "api/v1/configuration/ocpp-server/certificates/k1",          "certificates:edit")]
        [TestCase("DELETE",  "api/v1/configuration/ocpp-server/certificates/k1",          "certificates:edit")]
        [TestCase("GET",     "api/v1/configuration/ocpp-server/trust",                    "certificates:read")]
        [TestCase("POST",    "api/v1/configuration/ocpp-server/trust",                    "certificates:edit")]
        [TestCase("PUT",     "api/v1/configuration/ocpp-server/trust/t1",                 "certificates:edit")]
        [TestCase("DELETE",  "api/v1/configuration/ocpp-server/trust/t1",                 "certificates:edit")]
        [TestCase("GET",     "api/v1/certificates",                                       "certificates:read")]
        [TestCase("POST",    "api/v1/certificates",                                       "certificates:edit")]
        [TestCase("POST",    "api/v1/certificates/reload",                                "certificates:edit")]
        [TestCase("GET",     "api/v1/certificates/c1",                                    "certificates:read")]
        [TestCase("PATCH",   "api/v1/certificates/c1",                                    "certificates:edit")]
        [TestCase("DELETE",  "api/v1/certificates/c1",                                    "certificates:edit")]
        [TestCase("GET",     "api/v1/configuration/ocpi",                                 "roaming:read")]
        [TestCase("GET",     "api/v1/ocpi/partners",                                      "roaming:read")]
        [TestCase("POST",    "api/v1/ocpi/partners",                                      "roaming:edit")]
        [TestCase("POST",    "api/v1/ocpi/partners/2.2.1/p1/register",                    "roaming:edit")]
        [TestCase("DELETE",  "api/v1/ocpi/partners/2.2.1/p1",                             "roaming:edit")]
        [TestCase("GET",     "api/v1/ocpi/tokens",                                        "roaming:read")]
        [TestCase("GET",     "api/v1/ocpi/tariffs",                                       "roaming:read")]
        [TestCase("GET",     "api/v1/ocpi/sessions",                                      "roaming:read")]
        [TestCase("GET",     "api/v1/ocpi/cdrs",                                          "roaming:read")]
        [TestCase("GET",     "api/v1/ocpi/locations",                                     "locations:read")]
        [TestCase("POST",    "api/v1/ocpi/locations",                                     "locations:edit")]
        [TestCase("DELETE",  "api/v1/ocpi/locations/2.2.1/l1",                            "locations:edit")]
        public async Task EveryRouteAsksForItsOwnPermission(String Method, String Path, String Permission)
        {

            var roles = new JObject();

            foreach (var resource in new[] { "configuration", "dns", "nts", "certificates", "stations", "locations", "roaming" })
                foreach (var operation in new[] { "read", "edit", "run" })
                    roles.Add($"r-{resource}-{operation}", new JArray($"{resource}:{operation}"));

            await AStartedCSMS(new JObject(
                                   new JProperty("nts",    new JObject(new JProperty("enabled", false))),
                                   new JProperty("roles",  roles)
                               ));

            using var nobody  = await SignedInAs("nobody1", null);

            var response      = await nobody.SendAsync(new HttpRequestMessage(new HttpMethod(Method), Path) {
                                                           Content = Method == "GET"
                                                                         ? null
                                                                         : new StringContent("{}", Encoding.UTF8, "application/json")
                                                       });

            var refusal       = await response.Content.ReadAsStringAsync();

            // "This needs the r-dns-edit or cpo or systemadmin role." - the roles
            // of the file's that may, of which there has to be exactly one.
            var named         = System.Text.RegularExpressions.Regex.Matches(refusal, @"\br-[a-z]+-[a-z]+\b").
                                                                 Select(match => match.Value).
                                                                 Distinct().
                                                                 ToArray();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,  Is.EqualTo(HttpStatusCode.Forbidden), refusal);
                Assert.That(named,                Is.EqualTo(new[] { "r-" + Permission.Replace(':', '-') }),
                            $"{Method} {Path} asks for something else than {Permission}: {refusal}");
            });

        }

        #endregion

        #region TheClockIsForAnybodySignedIn()

        /// <summary>
        /// Whether the time here is worth anything is for anybody signed in, as
        /// the log and the event stream are - an account in no role at all
        /// included. Everything that is a resource is not.
        /// </summary>
        [Test]
        public async Task TheClockIsForAnybodySignedIn()
        {

            await AStartedCSMS();

            using var nobody   = await SignedInAs("nobody1", null);

            var clock          = await nobody.GetAsync("api/v1/clock");
            var configuration  = await nobody.GetAsync("api/v1/configuration");
            var refusal        = await configuration.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(clock.StatusCode,          Is.EqualTo(HttpStatusCode.OK));
                Assert.That(configuration.StatusCode,  Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(refusal,                   Does.Contain("This needs the viewer or cpo or systemadmin role."));
            });

        }

        #endregion

    }

}
