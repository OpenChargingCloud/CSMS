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

using cloud.charging.open.CSMS.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The OCPI side, over the wire: the versions a partner is shown, the
    /// endpoints they point at, a partner being added and signing in with the
    /// token it was given, a location being published and fetched, an EMSP
    /// pushing a token - and the peering itself, started from either end.
    /// </summary>
    /// <remarks>
    /// The partner in these tests is a plain HTTP client with an OCPI token,
    /// which is what an EMSP is from where this operator stands. For the two
    /// tests about the peering a stub EMSP is stood up on a port of its own:
    /// three routes, which is all the credentials handshake needs, whichever
    /// end starts it.
    /// </remarks>
    public class OCPITests : ACSMSTests
    {

        #region (private) Partner(Token)

        /// <summary>
        /// An EMSP calling this operator with the token it was given, encoded
        /// the way OCPI 2.2 sends it.
        /// </summary>
        private HttpClient Partner(String Token)
        {

            var http = new HttpClient { BaseAddress = new Uri(BaseURL) };

            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                           "Token",
                                                           Convert.ToBase64String(Encoding.UTF8.GetBytes(Token))
                                                       );

            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return http;

        }

        #endregion

        #region (private) AddPartner(HTTP, ...)

        /// <summary>
        /// Add a roaming partner through the JSON API, the way the web
        /// interface does, and hand back the token this operator made up for
        /// it.
        /// </summary>
        private async Task<(String Id, String Token, JObject Answer)> AddPartner(HttpClient  HTTP,
                                                                                 String      Version       = "2.2.1",
                                                                                 String      CountryCode   = "DE",
                                                                                 String      PartyId       = "GDF",
                                                                                 String?     TheirToken    = null,
                                                                                 String?     VersionsURL   = null)
        {

            var body = new List<JProperty> {
                           new ("version",      Version),
                           new ("countryCode",  CountryCode),
                           new ("partyId",      PartyId),
                           new ("role",         "EMSP"),
                           new ("name",         "Test EMSP"),
                           new ("website",      "https://emsp.example.org")
                       };

            if (TheirToken  is not null)  body.Add(new JProperty("theirToken",  TheirToken));
            if (VersionsURL is not null)  body.Add(new JProperty("versionsURL", VersionsURL));

            var response = await HTTP.PostAsync("/api/v1/ocpi/partners", JSONBody([.. body]));
            var text     = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created), $"Adding the partner answered {(Int32) response.StatusCode}: {text}");

            var answer = JObject.Parse(text);

            return (answer.Value<String>("id")!, answer.Value<String>("ourToken")!, answer);

        }

        #endregion

        #region (private) PublishLocation(HTTP, Id, Version)

        /// <summary>
        /// Publish a location through the JSON API, the way the web interface
        /// does.
        /// </summary>
        private async Task<JObject> PublishLocation(HttpClient  HTTP,
                                                    String      Id        = "LOC0001",
                                                    String      Version   = "2.2.1")
        {

            var response = await HTTP.PostAsync("/api/v1/ocpi/locations", JSONBody(
                                     new JProperty("version",     Version),
                                     new JProperty("id",          Id),
                                     new JProperty("name",        "Test location"),
                                     new JProperty("address",     "Biberweg 18"),
                                     new JProperty("postalCode",  "07749"),
                                     new JProperty("city",        "Jena"),
                                     new JProperty("country",     "DEU"),
                                     new JProperty("latitude",    50.927054),
                                     new JProperty("longitude",   11.589707),
                                     new JProperty("timeZone",    "Europe/Berlin")
                                 ));

            var text = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created), $"Publishing the location answered {(Int32) response.StatusCode}: {text}");

            return JObject.Parse(text);

        }

        #endregion

        #region (private static) OCPIResponse(Response)

        /// <summary>
        /// The OCPI envelope of an answer, with the HTTP status checked first
        /// so that a failing test says which of the two went wrong.
        /// </summary>
        private static async Task<JObject> OCPIResponse(HttpResponseMessage Response)
        {

            var text = await Response.Content.ReadAsStringAsync();

            Assert.That(Response.IsSuccessStatusCode, Is.True, $"{Response.RequestMessage?.Method} {Response.RequestMessage?.RequestUri} answered {(Int32) Response.StatusCode}: {text}");

            return JObject.Parse(text);

        }

        #endregion

        #region (private static) TokenJSON(Uid)

        /// <summary>
        /// The least an EMSP has to say about a token in OCPI 2.2.1.
        /// </summary>
        private static JObject TokenJSON(String Uid)

            => new (
                   new JProperty("country_code",  "DE"),
                   new JProperty("party_id",      "GDF"),
                   new JProperty("uid",           Uid),
                   new JProperty("type",          "RFID"),
                   new JProperty("contract_id",   "DE-GDF-C12345678-X"),
                   new JProperty("issuer",        "Test EMSP"),
                   new JProperty("valid",         true),
                   new JProperty("whitelist",     "ALLOWED"),
                   new JProperty("last_updated",  "2026-09-20T10:00:00Z")
               );

        #endregion

        #region TheVersionsAreListedForEverybody()

        /// <summary>
        /// The versions list is the one door a partner is given, and it is
        /// open: an EMSP that has not registered yet needs it to find the
        /// credentials endpoint. Every URL in it has to be one this operator
        /// actually serves, which means below the HTTPExt API's root.
        /// </summary>
        [Test]
        public async Task TheVersionsAreListedForEverybody()
        {

            using var http = Anonymous();

            var answer   = await OCPIResponse(await http.GetAsync("/ext/versions"));
            var versions = answer["data"] as JArray;

            Assert.That(versions, Is.Not.Null, "The versions list carries no data.");

            var listed = versions!.Select(version => version.Value<String>("version")).ToArray();

            Assert.Multiple(() => {

                Assert.That(answer.Value<Int32>("status_code"), Is.EqualTo(1000));
                Assert.That(listed, Is.EquivalentTo(OCPIConfiguration.DefaultVersions));

                foreach (var version in versions)
                    Assert.That(version.Value<String>("url"),
                                Is.EqualTo($"{BaseURL.TrimEnd('/')}/ext/versions/{version.Value<String>("version")}"),
                                "A version is advertised at a URL this operator does not serve.");

            });

        }

        #endregion

        #region TheVersionDetailsPointAtEndpointsThatExist()

        /// <summary>
        /// The library builds the URLs it advertises from the Host header and
        /// its own prefix, as if it sat at the root of the server; here it
        /// sits below "/ext". This is the test that says the two agree: every
        /// endpoint a partner is told about answers.
        /// </summary>
        [Test]
        public async Task TheVersionDetailsPointAtEndpointsThatExist()
        {

            using var admin = await SignedIn();

            var (_, token, _) = await AddPartner(admin);

            using var partner = Partner(token);

            var answer    = await OCPIResponse(await partner.GetAsync("/ext/versions/2.2.1"));
            var endpoints = answer["data"]?["endpoints"] as JArray;

            Assert.That(endpoints, Is.Not.Null.And.Not.Empty, "The version details carry no endpoints.");

            var identifiers = endpoints!.Select(endpoint => endpoint.Value<String>("identifier")).ToArray();

            Assert.Multiple(() => {
                Assert.That(identifiers, Does.Contain("credentials"));
                Assert.That(identifiers, Does.Contain("locations"));
                Assert.That(identifiers, Does.Contain("sessions"));
                Assert.That(identifiers, Does.Contain("cdrs"));
                Assert.That(identifiers, Does.Contain("tokens"));
            });

            foreach (var endpoint in endpoints)
            {

                var identifier = endpoint.Value<String>("identifier")!;
                var url        = new Uri(endpoint.Value<String>("url")!);

                Assert.That(url.AbsolutePath, Does.StartWith("/ext/v2.2.1/"),
                            $"The '{identifier}' endpoint is advertised outside the HTTPExt API, where nothing serves it.");

                // The library advertises a charging profiles module in the
                // version details of a CPO and serves no route for it - a gap
                // in the library, and a known one, so it is not what this test
                // is about.
                if (identifier == "chargingprofiles")
                    continue;

                // The tokens module of a CPO is addressed per party - an EMSP
                // PUTs below "tokens/{country_code}/{party_id}" - and has no
                // route at its base; the commands module is the same, one path
                // per command that an EMSP POSTs to. The party asked for here
                // is this operator's own, because the library serves that
                // route only for a party it holds assets for, and a partner's
                // is not one yet - see APartnerPushesATokenAndItShowsUp.
                var probe = await partner.GetAsync(
                                identifier switch {
                                    "tokens"    => new Uri(url + "/DE/GEF"),
                                    "commands"  => new Uri(url + "/START_SESSION"),
                                    _           => url
                                }
                            );

                // A 404 is the one answer that says the URL is wrong; a 405
                // says the route exists and GET is not how it is called.
                Assert.That(probe.StatusCode, Is.Not.EqualTo(HttpStatusCode.NotFound),
                            $"The '{identifier}' endpoint is advertised at {url} and not served there.");

            }

        }

        #endregion

        #region APartnerSignsInWithTheTokenItWasGiven()

        /// <summary>
        /// The whole of the first half of a peering: somebody adds the EMSP
        /// and is handed a token, the EMSP presents it, and this operator
        /// answers with its own credentials - which say where its versions
        /// are and who it is.
        /// </summary>
        [Test]
        public async Task APartnerSignsInWithTheTokenItWasGiven()
        {

            using var admin = await SignedIn();

            var (id, token, answer) = await AddPartner(admin);

            Assert.Multiple(() => {
                Assert.That(id,    Is.EqualTo("DE-GDF_EMSP"));
                Assert.That(token, Is.Not.Empty);
                Assert.That(answer["partner"]?.Value<Boolean>("registered"),  Is.False, "A partner that has not come yet is reported as registered.");
                Assert.That(answer["partner"]?.Value<Boolean>("canRegister"), Is.False, "A partner that handed out nothing is reported as registrable.");
            });

            var listed = (await GetJSON(admin, "/api/v1/ocpi/partners"))["partners"] as JArray;

            Assert.That(listed?.Select(partner => partner.Value<String>("id")), Does.Contain("DE-GDF_EMSP"));
            Assert.That(listed?.First(partner => partner.Value<String>("id") == "DE-GDF_EMSP").Value<String>("ourToken"), Is.EqualTo(token),
                        "The token is not shown to the administrator, who is the one who has to hand it over.");

            using var partner = Partner(token);

            var credentials = (await OCPIResponse(await partner.GetAsync("/ext/v2.2.1/credentials")))["data"];

            Assert.Multiple(() => {
                Assert.That(credentials?.Value<String>("token"), Is.EqualTo(token));
                Assert.That(credentials?.Value<String>("url"),   Is.EqualTo($"{BaseURL.TrimEnd('/')}/ext/versions"));
                Assert.That(credentials?["roles"]?.First?.Value<String>("role"),         Is.EqualTo("CPO"));
                Assert.That(credentials?["roles"]?.First?.Value<String>("party_id"),     Is.EqualTo("GEF"));
                Assert.That(credentials?["roles"]?.First?.Value<String>("country_code"), Is.EqualTo("DE"));
            });

        }

        #endregion

        #region AddingTheSamePartnerTwiceIsRefused()

        [Test]
        public async Task AddingTheSamePartnerTwiceIsRefused()
        {

            using var admin = await SignedIn();

            await AddPartner(admin);

            var again = await admin.PostAsync("/api/v1/ocpi/partners", JSONBody(
                                  new JProperty("version",      "2.1.1"),
                                  new JProperty("countryCode",  "DE"),
                                  new JProperty("partyId",      "GDF"),
                                  new JProperty("role",         "EMSP"),
                                  new JProperty("name",         "The same EMSP, on another version")
                              ));

            Assert.That(again.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                        "One EMSP on two versions is two partners with one identity, and the second was let in.");

        }

        #endregion

        #region ThisOperatorCannotBeItsOwnPartner()

        [Test]
        public async Task ThisOperatorCannotBeItsOwnPartner()
        {

            using var admin = await SignedIn();

            var itself = await admin.PostAsync("/api/v1/ocpi/partners", JSONBody(
                                   new JProperty("version",      "2.2.1"),
                                   new JProperty("countryCode",  "DE"),
                                   new JProperty("partyId",      "GEF"),
                                   new JProperty("role",         "CPO"),
                                   new JProperty("name",         "Us, again")
                               ));

            Assert.That(itself.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));

        }

        #endregion

        #region ALocationIsPublishedAndAPartnerCanFetchIt()

        /// <summary>
        /// What a CPO is for: it writes down where its stations are, and a
        /// partner that has registered reads it.
        /// </summary>
        [Test]
        public async Task ALocationIsPublishedAndAPartnerCanFetchIt()
        {

            using var admin = await SignedIn();

            await PublishLocation(admin);

            var listed = (await GetJSON(admin, "/api/v1/ocpi/locations"))["locations"] as JArray;

            Assert.That(listed, Is.Not.Null.And.Not.Empty, "The location was published and is not on the Locations page.");

            var location = listed!.First(item => item.Value<String>("id") == "LOC0001");

            Assert.Multiple(() => {
                Assert.That(location.Value<String>("version"),       Is.EqualTo("2.2.1"));
                Assert.That(location.Value<String>("name"),          Is.EqualTo("Test location"));
                Assert.That(location.Value<String>("city"),          Is.EqualTo("Jena"));
                Assert.That(location.Value<String>("country_code"),  Is.EqualTo("DE"));
                Assert.That(location.Value<String>("party_id"),      Is.EqualTo("GEF"));
            });

            var (_, token, _) = await AddPartner(admin);

            using var partner = Partner(token);

            var fetched = (await OCPIResponse(await partner.GetAsync("/ext/v2.2.1/cpo/locations")))["data"] as JArray;

            Assert.That(fetched?.Select(item => item.Value<String>("id")), Does.Contain("LOC0001"),
                        "The partner cannot fetch the location this operator published.");

            var counts = (await GetJSON(admin, "/api/v1/configuration/ocpi"))["counts"];

            Assert.That(counts?.Value<Int32>("locations"), Is.EqualTo(1));

            var withdrawn = await admin.DeleteAsync("/api/v1/ocpi/locations/2.2.1/LOC0001");

            Assert.That(withdrawn.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var remaining = (await GetJSON(admin, "/api/v1/ocpi/locations"))["locations"] as JArray;

            Assert.That(remaining?.Select(item => item.Value<String>("id")), Does.Not.Contain("LOC0001"));

        }

        #endregion

        #region ALocationWithoutAPlaceOnTheMapIsRefused()

        /// <summary>
        /// A location nobody can find is a location nobody is sent to, so it
        /// is not published at all.
        /// </summary>
        [Test]
        public async Task ALocationWithoutAPlaceOnTheMapIsRefused()
        {

            using var admin = await SignedIn();

            var refused = await admin.PostAsync("/api/v1/ocpi/locations", JSONBody(
                                    new JProperty("version",     "2.2.1"),
                                    new JProperty("id",          "LOC0009"),
                                    new JProperty("name",        "Nowhere"),
                                    new JProperty("address",     "Biberweg 18"),
                                    new JProperty("postalCode",  "07749"),
                                    new JProperty("city",        "Jena"),
                                    new JProperty("country",     "DEU"),
                                    new JProperty("timeZone",    "Europe/Berlin")
                                ));

            Assert.That(refused.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(await refused.Content.ReadAsStringAsync(), Does.Contain("latitude"));

        }

        #endregion

        #region ALocationInACountryNobodyHasHeardOfIsRefused()

        /// <summary>
        /// Refused rather than thrown over: a country that cannot be parsed is
        /// somebody's typo, and the answer says which field it was in.
        /// </summary>
        [Test]
        public async Task ALocationInACountryNobodyHasHeardOfIsRefused()
        {

            using var admin = await SignedIn();

            var refused = await admin.PostAsync("/api/v1/ocpi/locations", JSONBody(
                                    new JProperty("version",     "2.2.1"),
                                    new JProperty("id",          "LOC0010"),
                                    new JProperty("name",        "Somewhere"),
                                    new JProperty("address",     "Biberweg 18"),
                                    new JProperty("postalCode",  "07749"),
                                    new JProperty("city",        "Jena"),
                                    new JProperty("country",     "XYZ"),
                                    new JProperty("latitude",    50.927054),
                                    new JProperty("longitude",   11.589707),
                                    new JProperty("timeZone",    "Europe/Berlin")
                                ));

            Assert.That(refused.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(await refused.Content.ReadAsStringAsync(), Does.Contain("not a country"));

        }

        #endregion

        #region APartnerPushesATokenAndItShowsUp()

        /// <summary>
        /// The other direction: an EMSP PUTs one of its customers' tokens,
        /// and this operator holds it - which is what lets a station here
        /// authorise that card.
        /// </summary>
        /// <remarks>
        /// Written and then switched off, because the OCPI library cannot do
        /// it yet and this says exactly what is missing. It files every asset
        /// - locations, tariffs, tokens - under one of the parties the API was
        /// built for, and that same list is what the API answers "who are you"
        /// with: adding the pushing EMSP to it so that its tokens have
        /// somewhere to go would make this operator advertise itself as an
        /// EMSP as well, and send EMSP roles in its credentials. Somewhere to
        /// put a partner's assets that is not a claim about our own identity
        /// is a change to the library's data model, not to this CSMS - the
        /// EMSP side has one for the locations a CPO pushes
        /// (EMSP_HTTPAPI.AddRemoteCPO) and the CPO side has no counterpart.
        ///
        /// Until then the tokens page of this operator answers, and is empty.
        /// </remarks>
        [Test]
        [Ignore("The OCPI library has nowhere to file a token a partner pushed into a CPO; see the remarks.")]
        public async Task APartnerPushesATokenAndItShowsUp()
        {

            using var admin = await SignedIn();

            var (_, token, _) = await AddPartner(admin);

            using var partner = Partner(token);

            var put = await partner.PutAsync(
                                "/ext/v2.2.1/cpo/tokens/DE/GDF/0123456789ABCDEF",
                                new StringContent(TokenJSON("0123456789ABCDEF").ToString(), Encoding.UTF8, "application/json")
                            );

            var putText = await put.Content.ReadAsStringAsync();

            Assert.That(put.IsSuccessStatusCode, Is.True, $"PUT token answered {(Int32) put.StatusCode}: {putText}");
            Assert.That(JObject.Parse(putText).Value<Int32>("status_code"), Is.EqualTo(1000), putText);

            var tokens = (await GetJSON(admin, "/api/v1/ocpi/tokens"))["items"] as JArray;

            Assert.That(tokens, Is.Not.Null.And.Not.Empty, "The token the partner pushed is not on the Tokens page.");

            var pushed = tokens!.First(item => item.Value<String>("uid") == "0123456789ABCDEF");

            Assert.Multiple(() => {
                Assert.That(pushed.Value<String>("version"),      Is.EqualTo("2.2.1"));
                Assert.That(pushed.Value<String>("party_id"),     Is.EqualTo("GDF"));
                Assert.That(pushed.Value<String>("contract_id"),  Is.EqualTo("DE-GDF-C12345678-X"));
            });

            var counts = (await GetJSON(admin, "/api/v1/configuration/ocpi"))["counts"];

            Assert.That(counts?.Value<Int32>("tokens"), Is.EqualTo(1));

            Assert.That(CSMS.Log.Recent(500).Any(entry => entry.Message.Contains("0123456789ABCDEF", StringComparison.Ordinal)),
                        Is.True,
                        "A token arrived and the log does not say so.");

        }

        #endregion

        #region AnUnknownTokenCannotPush()

        /// <summary>
        /// An empty list of partners is "nobody", not "everybody".
        /// </summary>
        [Test]
        public async Task AnUnknownTokenIsTurnedAway()
        {

            using var stranger = Partner("nobody-gave-me-this");

            Assert.That((await stranger.GetAsync("/ext/versions")).IsSuccessStatusCode,
                        Is.False, "Somebody with a made-up token was let into this operator.");

            var put = await stranger.PutAsync(
                                "/ext/v2.2.1/cpo/tokens/DE/GDF/0123456789ABCDEF",
                                new StringContent(TokenJSON("0123456789ABCDEF").ToString(), Encoding.UTF8, "application/json")
                            );

            Assert.That(put.IsSuccessStatusCode, Is.False, "Somebody with a made-up token pushed a token into this operator.");

            using var admin = await SignedIn();

            var tokens = (await GetJSON(admin, "/api/v1/ocpi/tokens"))["items"] as JArray;

            Assert.That(tokens, Is.Empty);

        }

        #endregion

        #region ARemovedPartnerIsShutOut()

        [Test]
        public async Task ARemovedPartnerIsShutOut()
        {

            using var admin = await SignedIn();

            var (id, token, _) = await AddPartner(admin);

            using var partner = Partner(token);

            // At the versions list, which is where a partner starts and the
            // one endpoint that turns an unknown token away.
            Assert.That((await partner.GetAsync("/ext/versions")).IsSuccessStatusCode,
                        Is.True, "The partner could not get in before it was removed, so the test below proves nothing.");

            var removed = await admin.DeleteAsync($"/api/v1/ocpi/partners/2.2.1/{id}");

            Assert.That(removed.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            Assert.That((await partner.GetAsync("/ext/versions")).IsSuccessStatusCode,
                        Is.False, "A removed partner's token still opens this operator.");

            var listed = (await GetJSON(admin, "/api/v1/ocpi/partners"))["partners"] as JArray;

            Assert.That(listed, Is.Empty);

        }

        #endregion

        #region ThePartnersAreKeptBetweenStarts()

        /// <summary>
        /// The library writes its partners to files of its own beside the
        /// configuration and reads them back; a partner added today has to be
        /// there tomorrow, token and all.
        /// </summary>
        [Test]
        public async Task ThePartnersAreKeptBetweenStarts()
        {

            using var admin = await SignedIn();

            var (id, token, _) = await AddPartner(admin);

            await CSMS.Stop();

            var again = TestCSMSs.New(Directory, Configuration, Clock);

            try
            {

                await again.Start();

                var kept = again.OCPIVersions.SelectMany(version => version.RemoteParties).ToArray();

                Assert.Multiple(() => {
                    Assert.That(kept.Select(partner => partner.Id.ToString()), Does.Contain(id));
                    Assert.That(kept.First(partner => partner.Id.ToString() == id).OurToken?.ToString(), Is.EqualTo(token));
                    Assert.That(kept.First(partner => partner.Id.ToString() == id).Version,              Is.EqualTo("2.2.1"));
                });

            }
            finally
            {
                await again.DisposeAsync();
            }

        }

        #endregion

        #region TheCPORegistersWithAnEMSPOfItsOwnAccord()

        /// <summary>
        /// The peering with the CPO as the initiator: the EMSP handed out a
        /// token and its versions URL, and this operator goes there - fetches
        /// the versions, finds the credentials endpoint, POSTs its own
        /// credentials with a fresh token for the EMSP, and takes the EMSP's
        /// token from the answer.
        /// </summary>
        /// <remarks>
        /// The EMSP is a stub with the three routes the handshake touches. It
        /// records what it was sent, which is how the test knows this operator
        /// said the right things about itself.
        /// </remarks>
        [Test]
        public async Task TheCPORegistersWithAnEMSPOfItsOwnAccord()
        {

            using var admin = await SignedIn();

            await using var emsp = await StubEMSP.Start();

            var (id, ourTokenBefore, _) = await AddPartner(
                                                    admin,
                                                    TheirToken:   StubEMSP.TokenA,
                                                    VersionsURL:  emsp.VersionsURL
                                                );

            var before = ((await GetJSON(admin, "/api/v1/ocpi/partners"))["partners"] as JArray)!.
                             First(partner => partner.Value<String>("id") == id);

            Assert.Multiple(() => {
                Assert.That(before.Value<Boolean>("canRegister"), Is.True,  "A partner with a token and a versions URL is not offered for registration.");
                Assert.That(before.Value<Boolean>("registered"),  Is.False);
            });

            var register = await admin.PostAsync($"/api/v1/ocpi/partners/2.2.1/{id}/register", JSONBody());
            var text     = await register.Content.ReadAsStringAsync();

            Assert.That(register.StatusCode, Is.EqualTo(HttpStatusCode.OK), $"The registration answered {(Int32) register.StatusCode}: {text}");

            var answer = JObject.Parse(text);

            Assert.That(answer.Value<Boolean>("ok"), Is.True, answer.Value<String>("message"));

            var after = (answer["partners"]?["partners"] as JArray)!.First(partner => partner.Value<String>("id") == id);

            Assert.Multiple(() => {

                Assert.That(after.Value<Boolean>("registered"),   Is.True, "The registration went through and the partner is not reported as registered.");
                Assert.That(after.Value<String>("theirToken"),    Is.EqualTo(StubEMSP.TokenC), "The token the EMSP handed out in its answer was not taken.");
                Assert.That(after.Value<String>("remoteStatus"),  Is.EqualTo("ONLINE"));

                // What the EMSP was told.
                Assert.That(emsp.ReceivedCredentials, Is.Not.Null, "The EMSP never received this operator's credentials.");
                Assert.That(emsp.ReceivedCredentials?.Value<String>("url"),                        Is.EqualTo(CSMS.OCPIVersionsURL.ToString()));
                Assert.That(emsp.ReceivedCredentials?["roles"]?.First?.Value<String>("role"),      Is.EqualTo("CPO"));
                Assert.That(emsp.ReceivedCredentials?["roles"]?.First?.Value<String>("party_id"),  Is.EqualTo("GEF"));

                // The token this operator sent the EMSP is the one the EMSP
                // must use from now on - a fresh one, and the one the list
                // shows.
                Assert.That(emsp.ReceivedCredentials?.Value<String>("token"), Is.EqualTo(after.Value<String>("ourToken")));
                Assert.That(emsp.ReceivedCredentials?.Value<String>("token"), Is.Not.EqualTo(ourTokenBefore));

                // And it presented the token the EMSP had handed out.
                Assert.That(emsp.TokensSeen, Does.Contain(StubEMSP.TokenA));

            });

        }

        #endregion

        #region AnEMSPRegistersWithThisCPOOfItsOwnAccord()

        /// <summary>
        /// The same peering with the EMSP as the initiator, which is the more
        /// common way round: the operator adds the partner with nothing but a
        /// token, hands that token over, and the EMSP comes here - fetches the
        /// versions, finds the credentials endpoint, and POSTs its own
        /// credentials.
        /// </summary>
        /// <remarks>
        /// This operator then calls the EMSP back to fetch its versions, which
        /// is why the stub is listening for this direction too: a credentials
        /// POST naming a URL nobody answers at is not a registration, and the
        /// library is right to insist.
        ///
        /// What the EMSP is given in return is a new token of ours - the one
        /// it uses from now on - and the token it sent is what this operator
        /// uses towards it. Both ends hold both halves afterwards, which is
        /// exactly where the other direction ends up, and the two assertions
        /// at the bottom are the same ones.
        /// </remarks>
        [Test]
        public async Task AnEMSPRegistersWithThisCPOOfItsOwnAccord()
        {

            using var admin = await SignedIn();

            await using var emsp = await StubEMSP.Start();

            // Only a token of ours: nothing is known about where the EMSP is,
            // which is what makes this the other direction.
            var (id, ourToken, added) = await AddPartner(admin);

            Assert.That(added["partner"]?.Value<Boolean>("canRegister"), Is.False,
                        "Nothing was said about where the partner is and this operator thinks it could go there.");

            using var partner = Partner(ourToken);

            // What an EMSP does with the token it was handed: find the door ...
            var versions = (await OCPIResponse(await partner.GetAsync("/ext/versions")))["data"] as JArray;

            var details  = versions!.First(version => version.Value<String>("version") == "2.2.1").Value<String>("url");

            var endpoints = (await OCPIResponse(await partner.GetAsync(details)))["data"]?["endpoints"] as JArray;

            var credentialsURL = endpoints!.First(endpoint => endpoint.Value<String>("identifier") == "credentials").Value<String>("url")!;

            // ... and post its credentials through it.
            var posted = await partner.PostAsync(
                                   credentialsURL,
                                   new StringContent(
                                       new JObject(
                                           new JProperty("token",  StubEMSP.TokenC),
                                           new JProperty("url",    emsp.VersionsURL),
                                           new JProperty("roles",  new JArray(
                                               new JObject(
                                                   new JProperty("role",              "EMSP"),
                                                   new JProperty("party_id",          "GDF"),
                                                   new JProperty("country_code",      "DE"),
                                                   new JProperty("business_details",  new JObject(
                                                       new JProperty("name",  "Test EMSP")
                                                   ))
                                               )
                                           ))
                                       ).ToString(),
                                       Encoding.UTF8,
                                       "application/json"
                                   )
                               );

            var postedText = await posted.Content.ReadAsStringAsync();

            Assert.That(posted.IsSuccessStatusCode, Is.True, $"POST credentials answered {(Int32) posted.StatusCode}: {postedText}");

            var envelope = JObject.Parse(postedText);

            Assert.That(envelope.Value<Int32>("status_code"), Is.EqualTo(1000), postedText);

            var ours = envelope["data"];

            #region What the EMSP was answered with

            Assert.Multiple(() => {

                Assert.That(ours?.Value<String>("url"),                            Is.EqualTo(CSMS.OCPIVersionsURL.ToString()));
                Assert.That(ours?["roles"]?.First?.Value<String>("role"),          Is.EqualTo("CPO"));
                Assert.That(ours?["roles"]?.First?.Value<String>("party_id"),      Is.EqualTo("GEF"));
                Assert.That(ours?["roles"]?.First?.Value<String>("country_code"),  Is.EqualTo("DE"));

                // A fresh token: the one handed over by hand opened the door
                // once, and is spent.
                Assert.That(ours?.Value<String>("token"), Is.Not.Empty);
                Assert.That(ours?.Value<String>("token"), Is.Not.EqualTo(ourToken),
                            "The registration handed back the same token the partner came in with.");

            });

            #endregion

            #region And what this operator now holds

            var after = ((await GetJSON(admin, "/api/v1/ocpi/partners"))["partners"] as JArray)!.
                            First(candidate => candidate.Value<String>("id") == id);

            Assert.Multiple(() => {

                Assert.That(after.Value<Boolean>("registered"),   Is.True, "The EMSP registered and the partner is not reported as registered.");
                Assert.That(after.Value<String>("theirToken"),    Is.EqualTo(StubEMSP.TokenC), "The token the EMSP sent was not kept.");
                Assert.That(after.Value<String>("ourToken"),      Is.EqualTo(ours?.Value<String>("token")), "The token the EMSP was answered with is not the one this operator now expects.");
                Assert.That(after.Value<String>("theirVersionsURL"), Is.EqualTo(emsp.VersionsURL));

                // It went and looked: a credentials POST is believed only as
                // far as the versions URL in it answers.
                Assert.That(emsp.TokensSeen, Does.Contain(StubEMSP.TokenC),
                            "This operator never called the EMSP back with the token it was sent.");

            });

            #endregion

            // The token the EMSP came in with is spent, and the new one works.
            // Asked at the versions list, which is the one endpoint that turns
            // an unknown token away - the credentials endpoint answers anybody
            // who asks, because a partner has to be able to read what it is
            // registering against.
            using var withTheOldToken = Partner(ourToken);
            using var withTheNewToken = Partner(ours!.Value<String>("token")!);

            var withOld = await withTheOldToken.GetAsync("/ext/versions");

            Assert.That(withOld.IsSuccessStatusCode, Is.False,
                        $"The token handed over by hand still opens this operator after the registration replaced it: {(Int32) withOld.StatusCode} {await withOld.Content.ReadAsStringAsync()}");

            Assert.That((await withTheNewToken.GetAsync("/ext/versions")).IsSuccessStatusCode, Is.True,
                        "The token this operator handed back does not open it.");

        }

        #endregion

        #region (private) StubEMSP

        /// <summary>
        /// The three routes of an EMSP that the credentials handshake touches:
        /// the versions, the details of one, and the credentials endpoint.
        /// </summary>
        /// <remarks>
        /// Both directions need it. With the CPO as the initiator all three
        /// are called; with the EMSP as the initiator only the first two are,
        /// because it is this operator that calls back to see whether the URL
        /// in the credentials it was sent answers.
        /// </remarks>
        private sealed class StubEMSP : IAsyncDisposable
        {

            /// <summary>The token the EMSP handed out for this operator to call it with.</summary>
            public const String TokenA = "stub-emsp-token-a";

            /// <summary>The token the EMSP hands out in its credentials.</summary>
            public const String TokenC = "stub-emsp-token-c";

            private readonly HTTPServer server;

            public String    VersionsURL          { get; }

            public JObject?  ReceivedCredentials  { get; private set; }

            public List<String> TokensSeen        { get; } = [];


            private StubEMSP(HTTPServer Server, String VersionsURL)
            {
                this.server       = Server;
                this.VersionsURL  = VersionsURL;
            }


            public static async Task<StubEMSP> Start()
            {

                var port    = TestCSMSs.FreePort();
                var server  = new HTTPServer(IPAddress: IPv4Address.Localhost, TCPPort: IPPort.Parse(port));
                var origin  = $"http://127.0.0.1:{port}";
                var stub    = new StubEMSP(server, $"{origin}/versions");
                var api     = server.AddHTTPAPI(HTTPPath.Root);

                api.AddHandler(
                    HTTPPath.Parse("/versions"),
                    request => {
                        stub.Remember(request);
                        return Task.FromResult(JSON(request, new JArray(
                            new JObject(
                                new JProperty("version",  "2.2.1"),
                                new JProperty("url",      $"{origin}/versions/2.2.1")
                            )
                        )));
                    },
                    HTTPMethod.GET
                );

                api.AddHandler(
                    HTTPPath.Parse("/versions/2.2.1"),
                    request => {
                        stub.Remember(request);
                        return Task.FromResult(JSON(request, new JObject(
                            new JProperty("version",    "2.2.1"),
                            new JProperty("endpoints",  new JArray(
                                new JObject(
                                    new JProperty("identifier",  "credentials"),
                                    new JProperty("role",        "RECEIVER"),
                                    new JProperty("url",         $"{origin}/2.2.1/credentials")
                                )
                            ))
                        )));
                    },
                    HTTPMethod.GET
                );

                api.AddHandler(
                    HTTPPath.Parse("/2.2.1/credentials"),
                    request => {
                        stub.Remember(request);
                        stub.ReceivedCredentials = JObject.Parse(request.HTTPBodyAsUTF8String ?? "{}");
                        return Task.FromResult(JSON(request, new JObject(
                            new JProperty("token",  TokenC),
                            new JProperty("url",    stub.VersionsURL),
                            new JProperty("roles",  new JArray(
                                new JObject(
                                    new JProperty("role",              "EMSP"),
                                    new JProperty("party_id",          "GDF"),
                                    new JProperty("country_code",      "DE"),
                                    new JProperty("business_details",  new JObject(
                                        new JProperty("name",  "Stub EMSP")
                                    ))
                                )
                            ))
                        )));
                    },
                    HTTPMethod.POST
                );

                await server.Start();

                return stub;

            }


            private void Remember(HTTPRequest Request)
            {

                // The token as this operator presented it: base64 in OCPI 2.2,
                // which is what the assertion undoes.
                if (Request.Authorization is HTTPTokenAuthentication tokenAuth)
                {
                    try
                    {
                        TokensSeen.Add(Encoding.UTF8.GetString(Convert.FromBase64String(tokenAuth.Token)));
                    }
                    catch (FormatException)
                    {
                        TokensSeen.Add(tokenAuth.Token);
                    }
                }

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
            }

        }

        #endregion

    }

}
