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
using System.Net.Http.Headers;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.CSMS.OCPI;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// A credentials handshake while the file the OCPI library keeps the
    /// partners of a version in cannot be written.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This operator's registration with a partner was answered as done, or as
    /// a partner that did not go along, whatever the file did: where it refused
    /// the token the partner would call back with, the registration went out
    /// all the same; where it refused the partner's answer, the next start
    /// went back to the tokens from before, which the partner had let go of
    /// (WWCP_OCPI 594f03e0, d965a4ea and b1ab1995 say so now).
    /// </para>
    /// <para>
    /// The file is made unwritable the way that stops root as well: a
    /// directory where it would be. All three versions are offered, because
    /// each keeps its partners in a file of its own and is bound to this CSMS
    /// by an adapter of its own. The partner is a stub of the four routes the
    /// handshake touches, on a port of its own.
    /// </para>
    /// </remarks>
    public class RegistrationFileTests : ACSMSTests
    {

        #region Configuration - a CSMS that offers every version

        /// <summary>
        /// The default is 2.1.1 and 2.2.1.
        /// </summary>
        protected override JObject Configuration
            => PartnersFiles.EveryVersion;

        #endregion


        #region NothingIsSentWhereTheTokenToCallBackWithCannotBeStored(Version)

        /// <summary>
        /// A registration whose fresh token for the partner the file cannot
        /// take is not sent at all: 500 and why, the partner never hears of
        /// it, and the tokens are the ones from before.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task NothingIsSentWhereTheTokenToCallBackWithCannotBeStored(String Version)
        {

            using var admin = await SignedIn();

            await using var partner = await StubPartner.Start(Version);

            var (id, ourToken) = await AddPartner(admin, Version, partner);

            var file      = PartnersFiles.Block(CSMS, Version);

            var response  = await admin.PostAsync($"/api/v1/ocpi/partners/{Version}/{id}/register", JSONBody());
            var text      = await response.Content.ReadAsStringAsync();
            var listed    = await Listed(admin, id);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);
                Assert.That(text,  Does.Contain(Path.GetFileName(file)),     "The answer does not say which file refused.");
                Assert.That(text,  Does.Contain("Nothing was sent"),         "The answer does not say that nothing went out.");
                Assert.That(partner.ReceivedCredentials, Is.Null,            "The partner was sent credentials whose token this operator could not keep.");
                Assert.That(listed.Value<String>("ourToken"),   Is.EqualTo(ourToken),  "The token the partner calls with changed.");
                Assert.That(listed.Value<String>("theirToken"), Is.EqualTo(StubPartner.TokenA));
            });

        }

        #endregion

        #region ARegistrationThePartnerAcceptedStandsWhereItsFileRefusedIt(Version)

        /// <summary>
        /// A registration the partner accepted while the file refused its
        /// answer: 500 and why, with what to do about it - but in effect, the
        /// partner's new token in use, and written down with the next line the
        /// file takes, so that the next start knows it.
        /// </summary>
        /// <remarks>
        /// The partner makes the file unwritable once the credentials have
        /// arrived, before it answers: the token it is to call back with went
        /// into the file, its answer could not.
        /// </remarks>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task ARegistrationThePartnerAcceptedStandsWhereItsFileRefusedIt(String Version)
        {

            using var admin = await SignedIn();

            await using var partner = await StubPartner.Start(Version);

            var (id, _)   = await AddPartner(admin, Version, partner);

            var file      = PartnersFiles.FileOf(CSMS, Version);

            partner.WhenCredentialsArrive = () => PartnersFiles.Block(CSMS, Version);

            var response  = await admin.PostAsync($"/api/v1/ocpi/partners/{Version}/{id}/register", JSONBody());
            var text      = await response.Content.ReadAsStringAsync();
            var listed    = await Listed(admin, id);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);
                Assert.That(text,  Does.Contain(Path.GetFileName(file)),     "The answer does not say which file refused.");
                Assert.That(text,  Does.Contain("in effect"),                "The answer does not say that the registration stands.");
                Assert.That(text,  Does.Contain("Repair the file"),          "The answer does not say what to do.");
                Assert.That(partner.ReceivedCredentials, Is.Not.Null,        "The partner never received this operator's credentials.");
                Assert.That(listed.Value<String>("theirToken"), Is.EqualTo(StubPartner.TokenC), "The partner's new token is not the one in use.");
                Assert.That(listed.Value<String>("ourToken"),   Is.EqualTo(partner.ReceivedCredentials?.Value<String>("token")),
                            "The token the partner was sent is not the one this operator expects.");
            });

            // The next line the file takes writes the registration down first.
            PartnersFiles.Unblock(file);

            var other = await admin.PostAsync("/api/v1/ocpi/partners", JSONBody(
                                                                           new JProperty("version",      Version),
                                                                           new JProperty("countryCode",  "DE"),
                                                                           new JProperty("partyId",      "GDG"),
                                                                           new JProperty("role",         "EMSP"),
                                                                           new JProperty("name",         "Another EMSP")
                                                                       ));

            Assert.That(other.StatusCode, Is.EqualTo(HttpStatusCode.Created), await other.Content.ReadAsStringAsync());

            await CSMS.Stop();

            var again = await PartnersFiles.PartnerAfterARestart(Directory, Version, id);

            Assert.That(again?.TheirToken?.ToString(), Is.EqualTo(StubPartner.TokenC),
                        "The next start does not know the registration the partner accepted.");

        }

        #endregion

        #region ALineThePartnersFileRefusesIsAnErrorInTheLog(Version)

        /// <summary>
        /// A line the file of the partners refuses is an error in the log,
        /// tagged "ocpi" and "files": the file, the command and why - and not
        /// the line, which holds tokens.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task ALineThePartnersFileRefusesIsAnErrorInTheLog(String Version)
        {

            using var admin = await SignedIn();

            var file      = PartnersFiles.Block(CSMS, Version);

            var response  = await admin.PostAsync("/api/v1/ocpi/partners", JSONBody(
                                                                               new JProperty("version",      Version),
                                                                               new JProperty("countryCode",  "DE"),
                                                                               new JProperty("partyId",      "GDF"),
                                                                               new JProperty("role",         "EMSP"),
                                                                               new JProperty("name",         "Test EMSP"),
                                                                               new JProperty("ourToken",     "a-token-the-log-must-not-hold")
                                                                           ));

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), await response.Content.ReadAsStringAsync());

            var said = CSMS.Log.Recent(100, Tag: "files").ToArray();

            Assert.That(said, Has.Length.EqualTo(1), "The line the file of the partners refused is not in the log, or more than once.");

            Assert.Multiple(() => {
                Assert.That(said[0].Level,    Is.EqualTo(LogLevel.Error));
                Assert.That(said[0].Tags,     Does.Contain("ocpi"));
                Assert.That(said[0].Message,  Does.Contain(Path.GetFileName(file)),                      "The log does not say which file refused.");
                Assert.That(said[0].Message,  Does.Contain(protocols.OCPI.CommonHTTPAPI.addRemoteParty), "The log does not say what the file refused.");
                Assert.That(said[0].Message,  Does.Contain($"OCPI {Version}"),                           "The log does not say which version.");
                Assert.That(said[0].Message,  Does.Not.Contain("a-token-the-log-must-not-hold"),         "The line itself is in the log.");
            });

        }

        #endregion

        #region APartnerAddedHereRegistersWithIt(Version)

        /// <summary>
        /// A partner added here with nothing but a token of ours registers with
        /// it: its credentials taken, ours answered, and the token it came in
        /// with spent.
        /// </summary>
        /// <remarks>
        /// In OCPI 2.1.1 every such registration ended in 500: the library
        /// took the first of the partner's remote access infos, and one added
        /// with only a token of ours has none (fixed in WWCP_OCPI b1ab1995).
        /// </remarks>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task APartnerAddedHereRegistersWithIt(String Version)
        {

            using var admin = await SignedIn();

            await using var partner = await StubPartner.Start(Version);

            var (id, ourToken) = await AddPartner(admin, Version);

            var (status, envelope) = await PostCredentials(Version, ourToken, partner);

            Assert.Multiple(() => {
                Assert.That(status,                                  Is.EqualTo(HttpStatusCode.OK), envelope.ToString());
                Assert.That(envelope.Value<Int32>("status_code"),    Is.EqualTo(1000),              envelope.ToString());
                Assert.That(envelope["data"]?.Value<String>("token"), Is.Not.Null.And.Not.EqualTo(ourToken),
                            "The registration did not hand back a fresh token.");
            });

            var listed = await Listed(admin, id);

            Assert.Multiple(() => {
                Assert.That(listed.Value<String>("theirToken"), Is.EqualTo(StubPartner.TokenC), "The token the partner sent was not kept.");
                Assert.That(listed.Value<String>("ourToken"),   Is.EqualTo(envelope["data"]?.Value<String>("token")));
            });

        }

        #endregion

        #region APartnerRegisteringWhileItsFileRefusesKeepsItsToken(Version)

        /// <summary>
        /// A partner registering here while the file of the partners refuses
        /// is answered OCPI 3000 with HTTP 500, and nothing changes: the token
        /// it came in with still opens this operator, to try again with.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task APartnerRegisteringWhileItsFileRefusesKeepsItsToken(String Version)
        {

            using var admin = await SignedIn();

            await using var partner = await StubPartner.Start(Version);

            var (id, ourToken) = await AddPartner(admin, Version);

            PartnersFiles.Block(CSMS, Version);

            var (status, envelope) = await PostCredentials(Version, ourToken, partner);

            Assert.Multiple(() => {
                Assert.That(status,                                Is.EqualTo(HttpStatusCode.InternalServerError), envelope.ToString());
                Assert.That(envelope.Value<Int32>("status_code"),  Is.EqualTo(3000),                               envelope.ToString());
            });

            using var withTheSameToken = Partner(ourToken, Version);

            var versions = await withTheSameToken.GetAsync("/ext/versions");

            Assert.That(versions.IsSuccessStatusCode, Is.True,
                        $"The token the partner came in with no longer opens this operator: {(Int32) versions.StatusCode} {await versions.Content.ReadAsStringAsync()}");

            Assert.That((await Listed(admin, id)).Value<String>("ourToken"), Is.EqualTo(ourToken));

        }

        #endregion


        #region (private) AddPartner(Admin, Version, Partner = null)

        /// <summary>
        /// Add an EMSP on the given version through the JSON API, and hand back
        /// its identification and the token this operator made up for it. With
        /// a stub partner, also the token that partner handed out and its
        /// versions URL, which is what lets this operator register with it.
        /// </summary>
        private static async Task<(String Id, String OurToken)> AddPartner(HttpClient    Admin,
                                                                           String        Version,
                                                                           StubPartner?  Partner   = null)
        {

            var body = new List<JProperty> {
                           new ("version",      Version),
                           new ("countryCode",  "DE"),
                           new ("partyId",      "GDF"),
                           new ("role",         "EMSP"),
                           new ("name",         "Test EMSP")
                       };

            if (Partner is not null)
            {
                body.Add(new JProperty("theirToken",   StubPartner.TokenA));
                body.Add(new JProperty("versionsURL",  Partner.VersionsURL));
            }

            var response  = await Admin.PostAsync("/api/v1/ocpi/partners", JSONBody([.. body]));
            var text      = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created),
                        $"Adding the partner answered {(Int32) response.StatusCode}: {text}");

            var answer = JObject.Parse(text);

            return (answer.Value<String>("id")!, answer.Value<String>("ourToken")!);

        }

        #endregion

        #region (private static) Listed(Admin, Id)

        /// <summary>
        /// The partner as the JSON API lists it, its tokens among it.
        /// </summary>
        private static async Task<JObject> Listed(HttpClient Admin, String Id)

            => ((await GetJSON(Admin, "/api/v1/ocpi/partners"))["partners"] as JArray)!.
                   OfType<JObject>().
                   First(partner => partner.Value<String>("id") == Id);

        #endregion

        #region (private) Partner(Token, Version)

        /// <summary>
        /// A partner calling this operator with a token: base64 from OCPI 2.2
        /// on, as it is, in OCPI 2.1.1.
        /// </summary>
        private HttpClient Partner(String Token, String Version)
        {

            var http = new HttpClient { BaseAddress = new Uri(BaseURL) };

            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                           "Token",
                                                           Version == "2.1.1"
                                                               ? Token
                                                               : Convert.ToBase64String(Encoding.UTF8.GetBytes(Token))
                                                       );

            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return http;

        }

        #endregion

        #region (private) PostCredentials(Version, Token, Stub)

        /// <summary>
        /// What a partner does with the token it was handed: find this
        /// operator's credentials endpoint of the version, and post its own
        /// credentials there - its token C and the versions URL of the stub,
        /// which this operator calls back.
        /// </summary>
        private async Task<(HttpStatusCode Status, JObject Envelope)> PostCredentials(String       Version,
                                                                                      String       Token,
                                                                                      StubPartner  Stub)
        {

            using var partner   = Partner(Token, Version);

            var versions        = (await Envelope(await partner.GetAsync("/ext/versions")))["data"] as JArray;
            var details         = versions!.First(version => version.Value<String>("version") == Version).Value<String>("url");
            var endpoints       = (await Envelope(await partner.GetAsync(details)))["data"]?["endpoints"] as JArray;
            var credentialsURL  = endpoints!.First(endpoint => endpoint.Value<String>("identifier") == "credentials").Value<String>("url")!;

            var posted          = await partner.PostAsync(
                                            credentialsURL,
                                            new StringContent(
                                                StubPartner.Credentials(Version, StubPartner.TokenC, Stub.VersionsURL).ToString(),
                                                Encoding.UTF8,
                                                "application/json"
                                            )
                                        );

            var text            = await posted.Content.ReadAsStringAsync();

            return (posted.StatusCode, String.IsNullOrEmpty(text) ? new JObject() : JObject.Parse(text));

        }

        #endregion

        #region (private static) Envelope(Response)

        private static async Task<JObject> Envelope(HttpResponseMessage Response)
        {

            var text = await Response.Content.ReadAsStringAsync();

            Assert.That(Response.IsSuccessStatusCode, Is.True, $"{(Int32) Response.StatusCode}: {text}");

            return JObject.Parse(text);

        }

        #endregion

    }


    /// <summary>
    /// A registration the partner accepted and the file of the partners
    /// refused, when the CSMS stops: written down then, where the file takes
    /// it at last - even where stopping throws - and an error in the log where
    /// it still does not, because the next start will not know it.
    /// </summary>
    /// <remarks>
    /// Each test makes a CSMS of its own and disposes it itself, rather than
    /// the one of a fixture, whose TearDown would dispose it a second time.
    /// </remarks>
    [TestFixture]
    public class RegistrationAtTheStopTests
    {

        #region ARegistrationKeptIsWrittenDownWhenTheCSMSStops(Version)

        /// <summary>
        /// Kept while the file refused it, and the file mended before the
        /// CSMS stops: the next start knows the registration, and nothing in
        /// the log says it is lost.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task ARegistrationKeptIsWrittenDownWhenTheCSMSStops(String Version)
        {

            var directory = TestCSMSs.TemporaryDirectory("registration-kept");

            try
            {

                await using var partner = await StubPartner.Start(Version);

                var csms  = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(directory, PartnersFiles.EveryVersion));
                var id    = await KeptRegistration(csms, Version, partner);

                PartnersFiles.Unblock(PartnersFiles.FileOf(csms, Version));

                await csms.DisposeAsync();

                Assert.That(Lost(csms), Is.Empty, "A registration that was written down is said to be lost.");

                var again = await PartnersFiles.PartnerAfterARestart(directory, Version, id);

                Assert.That(again?.TheirToken?.ToString(), Is.EqualTo(StubPartner.TokenC),
                            "The next start does not know the registration the partner accepted.");

            }
            finally
            {
                TestCSMSs.Remove(directory);
            }

        }

        #endregion

        #region ARegistrationTheFileStillRefusesWhenTheCSMSStopsIsSaidToBeLost(Version)

        /// <summary>
        /// Kept while the file refused it, and the file still refusing when the
        /// CSMS stops: an error in the log, naming the partner, that the next
        /// start will not know it.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task ARegistrationTheFileStillRefusesWhenTheCSMSStopsIsSaidToBeLost(String Version)
        {

            var directory = TestCSMSs.TemporaryDirectory("registration-lost");

            try
            {

                await using var partner = await StubPartner.Start(Version);

                var csms  = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(directory, PartnersFiles.EveryVersion));
                var id    = await KeptRegistration(csms, Version, partner);

                await csms.DisposeAsync();

                var lost  = Lost(csms);

                Assert.That(lost, Has.Length.EqualTo(1), "The registration the file still refused is not said to be lost, or more than once.");

                Assert.Multiple(() => {
                    Assert.That(lost[0].Level,    Is.EqualTo(LogLevel.Error));
                    Assert.That(lost[0].Tags,     Does.Contain("ocpi"));
                    Assert.That(lost[0].Message,  Does.Contain(id));
                    Assert.That(lost[0].Message,  Does.Contain($"OCPI {Version}"));
                });

            }
            finally
            {
                TestCSMSs.Remove(directory);
            }

        }

        #endregion

        #region ARegistrationKeptIsWrittenDownEvenWhereStoppingThrows()

        /// <summary>
        /// Stopping throws, and the CSMS is disposed all the same: what the
        /// OCPI library still holds is written down, and the next start knows
        /// the registration.
        /// </summary>
        [Test]
        public async Task ARegistrationKeptIsWrittenDownEvenWhereStoppingThrows()
        {

            var directory = TestCSMSs.TemporaryDirectory("registration-throws");

            try
            {

                await using var partner = await StubPartner.Start("2.2.1");

                var csms  = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(directory, PartnersFiles.EveryVersion));
                var id    = await KeptRegistration(csms, "2.2.1", partner);

                PartnersFiles.Unblock(PartnersFiles.FileOf(csms, "2.2.1"));

                // Once: the node below stops again as it is disposed.
                csms.WhileStopping = () => {
                    csms.WhileStopping = null;
                    throw new InvalidOperationException("Stopping failed, on purpose.");
                };

                Assert.ThrowsAsync<InvalidOperationException>(async () => await csms.DisposeAsync());

                var again = await PartnersFiles.PartnerAfterARestart(directory, "2.2.1", id);

                Assert.That(again?.TheirToken?.ToString(), Is.EqualTo(StubPartner.TokenC),
                            "Where stopping threw, the registration the partner accepted was not written down.");

            }
            finally
            {
                TestCSMSs.Remove(directory);
            }

        }

        #endregion


        #region (private static) KeptRegistration(CSMS, Version, Partner)

        /// <summary>
        /// Add the partner and register with it, the partner making the file
        /// of the partners unwritable once the credentials have arrived: the
        /// registration is in effect, and kept unwritten.
        /// </summary>
        private static async Task<String> KeptRegistration(CSMS         CSMS,
                                                           String       Version,
                                                           StubPartner  Partner)
        {

            var added = await CSMS.AddRemotePartyAsync(
                                  new JObject(
                                      new JProperty("version",      Version),
                                      new JProperty("countryCode",  "DE"),
                                      new JProperty("partyId",      "GDF"),
                                      new JProperty("role",         "EMSP"),
                                      new JProperty("name",         "Test EMSP"),
                                      new JProperty("theirToken",   StubPartner.TokenA),
                                      new JProperty("versionsURL",  Partner.VersionsURL)
                                  )
                              );

            Assert.That(added.Success, Is.True, added.Message);

            var id = added.Data?.Value<String>("id")!;

            Partner.WhenCredentialsArrive = () => PartnersFiles.Block(CSMS, Version);

            var registered = await CSMS.RegisterRemotePartyAsync(Version, id);

            Assert.Multiple(() => {
                Assert.That(registered.Success,  Is.False, registered.Message);
                Assert.That(registered.NotSaved, Is.True,  registered.Message);
                Assert.That(Partner.ReceivedCredentials, Is.Not.Null, "The partner never received this operator's credentials.");
            });

            return id;

        }

        #endregion

        #region (private static) Lost(CSMS)

        /// <summary>
        /// What the log of a CSMS says the next start will not know.
        /// </summary>
        private static LogEntry[] Lost(CSMS CSMS)

            => [.. CSMS.Log.Recent(100, Tag: "files").Where(entry => entry.Message.Contains("the next start will not know"))];

        #endregion

    }


    #region (internal static) PartnersFiles

    /// <summary>
    /// The files the OCPI library keeps the partners of a version in: which
    /// one, and how a test makes it unwritable and mends it again.
    /// </summary>
    internal static class PartnersFiles
    {

        /// <summary>
        /// A configuration offering every OCPI version, the time client off.
        /// </summary>
        public static JObject EveryVersion

            => new (
                   new JProperty("nts",   new JObject(
                       new JProperty("enabled",  false)
                   )),
                   new JProperty("ocpi",  new JObject(
                       new JProperty("versions",  new JArray("2.1.1", "2.2.1", "2.3.0"))
                   ))
               );

        /// <summary>
        /// The file the library keeps the partners of a version in.
        /// </summary>
        public static String FileOf(CSMS CSMS, String Version)

            => Path.Combine(
                   CSMS.OCPIDirectory,
                   Version switch {
                       "2.1.1"  => protocols.OCPIv2_1_1.CommonAPI.DefaultRemotePartyDBFileName,
                       "2.2.1"  => protocols.OCPIv2_2_1.CommonAPI.DefaultRemotePartyDBFileName,
                       "2.3.0"  => protocols.OCPIv2_3_0.CommonAPI.DefaultRemotePartyDBFileName,
                       _        => throw new ArgumentException($"This CSMS offers no OCPI {Version}.", nameof(Version))
                   }
               );

        /// <summary>
        /// Make the file the library keeps the partners of a version in
        /// unwritable: a directory where it is, which stops root as well. What
        /// it held is put aside, for <see cref="Unblock"/> to put back.
        /// </summary>
        public static String Block(CSMS CSMS, String Version)
        {

            var file = FileOf(CSMS, Version);

            if (File.Exists(file))
                File.Move(file, file + ".aside");

            System.IO.Directory.CreateDirectory(file);

            return file;

        }

        /// <summary>
        /// Mend what <see cref="Block"/> did: the directory gone, and what the
        /// file held back where it was.
        /// </summary>
        public static void Unblock(String File)
        {

            if (System.IO.Directory.Exists(File))
                System.IO.Directory.Delete(File);

            if (System.IO.File.Exists(File + ".aside"))
                System.IO.File.Move(File + ".aside", File);

        }

        /// <summary>
        /// The partner as the next start in the same directory knows it - none
        /// where it does not. The CSMS before must have stopped.
        /// </summary>
        public static async Task<RemotePartySummary?> PartnerAfterARestart(String  Directory,
                                                                          String  Version,
                                                                          String  Id)
        {

            // Made again, on fresh ports, where another test run on this
            // machine took one before the CSMS could bind it - in the same
            // directory all the same, so every attempt reads the same files.
            var again = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(Directory, EveryVersion));

            try
            {
                return again.OCPIVersions.
                           Where      (version => version.Label == Version).
                           SelectMany (version => version.RemoteParties).
                           FirstOrDefault(partner => partner.Id.ToString() == Id);
            }
            finally
            {
                await again.DisposeAsync();
            }

        }

    }

    #endregion

    #region (internal) StubPartner

    /// <summary>
    /// The four routes of an EMSP that the credentials handshake touches, in
    /// one OCPI version: the versions, the details of the one, and the
    /// credentials endpoint - which this operator posts to when it registers,
    /// and which a partner registering here is called back at.
    /// </summary>
    internal sealed class StubPartner : IAsyncDisposable
    {

        /// <summary>The token the partner handed out for this operator to call it with.</summary>
        public const String TokenA = "stub-partner-token-a";

        /// <summary>The token the partner hands out in its credentials.</summary>
        public const String TokenC = "stub-partner-token-c";

        private readonly HTTPServer  server;

        /// <summary>
        /// The port the stub's server is on, held from before it starts until
        /// it has stopped, so that nobody asking for a free port is given it in
        /// between - see <see cref="ClosedPort"/>.
        /// </summary>
        private readonly ClosedPort  port;

        public String    Version              { get; }

        public String    VersionsURL          { get; }

        /// <summary>
        /// What this operator posted to the credentials endpoint, if anything.
        /// </summary>
        public JObject?  ReceivedCredentials  { get; private set; }

        /// <summary>
        /// Something to do once this operator's credentials have arrived,
        /// before the answer goes back: a test making a file unwritable there,
        /// say.
        /// </summary>
        public Action?   WhenCredentialsArrive  { get; set; }


        private StubPartner(HTTPServer Server, ClosedPort Port, String Version, String VersionsURL)
        {
            this.server       = Server;
            this.port         = Port;
            this.Version      = Version;
            this.VersionsURL  = VersionsURL;
        }


        public static async Task<StubPartner> Start(String Version)
        {

            var port    = new ClosedPort();

            port.HandOver();

            var server  = new HTTPServer(IPAddress: IPv4Address.Localhost, TCPPort: port.Number);
            var origin  = $"http://127.0.0.1:{port}";
            var stub    = new StubPartner(server, port, Version, $"{origin}/versions");
            var api     = server.AddHTTPAPI(HTTPPath.Root);

            api.AddHandler(
                HTTPPath.Parse("/versions"),
                request => Task.FromResult(JSON(request, new JArray(
                    new JObject(
                        new JProperty("version",  Version),
                        new JProperty("url",      $"{origin}/versions/{Version}")
                    )
                ))),
                HTTPMethod.GET
            );

            // OCPI 2.1.1 says nothing of an endpoint's role; from 2.2 on the
            // credentials endpoint is a receiver.
            var credentialsEndpoint = new JObject(
                                          new JProperty("identifier",  "credentials"),
                                          new JProperty("url",         $"{origin}/{Version}/credentials")
                                      );

            if (Version != "2.1.1")
                credentialsEndpoint.Add(new JProperty("role", "RECEIVER"));

            api.AddHandler(
                HTTPPath.Parse($"/versions/{Version}"),
                request => Task.FromResult(JSON(request, new JObject(
                    new JProperty("version",    Version),
                    new JProperty("endpoints",  new JArray(credentialsEndpoint))
                ))),
                HTTPMethod.GET
            );

            api.AddHandler(
                HTTPPath.Parse($"/{Version}/credentials"),
                request => {
                    stub.ReceivedCredentials = JObject.Parse(request.HTTPBodyAsUTF8String ?? "{}");
                    stub.WhenCredentialsArrive?.Invoke();
                    return Task.FromResult(JSON(request, Credentials(Version, TokenC, stub.VersionsURL)));
                },
                HTTPMethod.POST
            );

            await server.Start();

            return stub;

        }


        /// <summary>
        /// The credentials of an EMSP in the shape of the version: its party
        /// beside the token in OCPI 2.1.1, a list of roles from 2.2 on.
        /// </summary>
        public static JObject Credentials(String Version, String Token, String VersionsURL)
        {

            var businessDetails = new JObject(
                                      new JProperty("name",  "Stub EMSP")
                                  );

            return Version == "2.1.1"

                       ? new JObject(
                             new JProperty("token",             Token),
                             new JProperty("url",               VersionsURL),
                             new JProperty("business_details",  businessDetails),
                             new JProperty("party_id",          "GDF"),
                             new JProperty("country_code",      "DE")
                         )

                       : new JObject(
                             new JProperty("token",  Token),
                             new JProperty("url",    VersionsURL),
                             new JProperty("roles",  new JArray(
                                 new JObject(
                                     new JProperty("role",              "EMSP"),
                                     new JProperty("party_id",          "GDF"),
                                     new JProperty("country_code",      "DE"),
                                     new JProperty("business_details",  businessDetails)
                                 )
                             ))
                         );

        }


        private static HTTPResponse JSON(HTTPRequest Request, JToken Data)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode  = HTTPStatusCode.OK,
                   ContentType     = HTTPContentType.Application.JSON_UTF8,
                   Content         = Encoding.UTF8.GetBytes(
                                         new JObject(
                                             new JProperty("data",            Data),
                                             new JProperty("status_code",     1000),
                                             new JProperty("status_message",  "OK"),
                                             new JProperty("timestamp",       DateTimeOffset.UtcNow.ToString("o"))
                                         ).ToString()
                                     ),
                   Connection      = ConnectionType.Close
               }.AsImmutable;


        public async ValueTask DisposeAsync()
        {
            await server.Stop();
            port.Dispose();
        }

    }

    #endregion

}
