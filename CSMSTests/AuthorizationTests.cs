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

using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.OCPPv2_1;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// A charging station's Authorize, answered with what the roaming partners
    /// said of the card.
    /// </summary>
    /// <remarks>
    /// The OCPP node answered every Authorize by itself: "Invalid" of every
    /// card a partner had sent, as nothing filled its list, and "Accepted" of
    /// three cards it knows for testing, which are nobody's. A plain HTTP
    /// client stands in for the partner and pushes the cards over OCPI 2.2.1,
    /// and a plain WebSocket client for the station that asks.
    /// </remarks>
    [TestFixture]
    public class AuthorizationTests : ACSMSTests
    {

        #region Data

        private const String  ThePassword  = "a-password-long-enough-for-ocpp";

        private const String  AValidCard   = "04A2B3C4D5E6F7";
        private const String  NotValid     = "04BBBBBBBBBBBB";
        private const String  AskedOfItsPartner = "04DDDDDDDDDDDD";
        private const String  NobodysCard  = "04CCCCCCCCCCCC";

        #endregion

        #region (override) Configuration

        protected override JObject Configuration
        {
            get
            {

                var configuration = TestCSMSs.LoopbackPartners(TestCSMSs.Offline);

                configuration.Add(new JProperty("ocppServer", new JObject(
                    new JProperty("enabled",           true),
                    new JProperty("address",           "127.0.0.1"),
                    new JProperty("port",              TestPorts.Free()),
                    new JProperty("securityProfiles",  new JArray(1)),
                    new JProperty("subprotocols",      new JArray("ocpp2.1"))
                )));

                return configuration;

            }
        }

        #endregion

        #region SetUp

        [SetUp]
        public async Task APartnerPushesItsCards()
        {

            var added = await CSMS.AddRemotePartyAsync(new JObject(
                                       new JProperty("version",      "2.2.1"),
                                       new JProperty("countryCode",  "DE"),
                                       new JProperty("partyId",      "GDF"),
                                       new JProperty("role",         "EMSP"),
                                       new JProperty("name",         "Test EMSP")
                                   ));

            Assert.That(added.Success, Is.True, added.Message);

            using var partner = new HttpClient { BaseAddress = new Uri(BaseURL) };

            partner.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                              "Token",
                                                              Convert.ToBase64String(Encoding.UTF8.GetBytes(added.Data!.Value<String>("ourToken")!))
                                                          );

            partner.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            foreach (var (uid, valid, whitelist) in new[] {
                                                       (AValidCard,         true,   "ALLOWED"),
                                                       (NotValid,           false,  "ALLOWED"),
                                                       (AskedOfItsPartner,  true,   "NEVER")
                                                   })
            {

                var put  = await partner.PutAsync(
                                     $"/ext/v2.2.1/cpo/tokens/DE/GDF/{uid}",
                                     new StringContent(new JObject(
                                         new JProperty("country_code",  "DE"),
                                         new JProperty("party_id",      "GDF"),
                                         new JProperty("uid",           uid),
                                         new JProperty("type",          "RFID"),
                                         new JProperty("contract_id",   "DE-GDF-C12345678-X"),
                                         new JProperty("issuer",        "Test EMSP"),
                                         new JProperty("valid",         valid),
                                         new JProperty("whitelist",     whitelist),
                                         new JProperty("last_updated",  "2026-11-01T10:00:00Z")
                                     ).ToString(), Encoding.UTF8, "application/json")
                                 );

                var text = await put.Content.ReadAsStringAsync();

                Assert.That(put.IsSuccessStatusCode, Is.True, $"PUT of the card {uid} answered {(Int32) put.StatusCode}: {text}");

            }

        }

        #endregion

        #region (private) AStationAsksAbout(UID)

        /// <summary>
        /// A station signed in with a password asks about a card, and what it
        /// is answered: the idTokenInfo of the CALLRESULT.
        /// </summary>
        private async Task<JObject> AStationAsksAbout(String UID)
        {

            Assert.That(CSMS.StationLogins.TrySetPassword("cs001", ThePassword, null, null, out _, out var error), Is.True, error);

            using var station = new ClientWebSocket();

            station.Options.AddSubProtocol("ocpp2.1");
            station.Options.SetRequestHeader("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"cs001:{ThePassword}")));

            await station.ConnectAsync(new Uri($"ws://127.0.0.1:{CSMS.OCPPServerSettings.TCPPort}"), CancellationToken.None);

            var request = new JArray(2, "asked-1", "Authorize", new JObject(
                              new JProperty("idToken", new JObject(
                                  new JProperty("idToken",  UID),
                                  new JProperty("type",     "ISO14443")
                              ))
                          ));

            await station.SendAsync(Encoding.UTF8.GetBytes(request.ToString(Newtonsoft.Json.Formatting.None)), WebSocketMessageType.Text, true, CancellationToken.None);

            using var patience  = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var buffer          = new Byte[1 << 16];

            while (true)
            {

                var text = new StringBuilder();
                WebSocketReceiveResult result;

                do
                {
                    result = await station.ReceiveAsync(buffer, patience.Token);
                    text.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                }
                while (!result.EndOfMessage);

                var frame = JArray.Parse(text.ToString());

                // Whatever the CSMS asks by itself in between is not the answer.
                if (frame[1]?.Value<String>() != "asked-1")
                    continue;

                Assert.That(frame[0]!.Value<Int32>(), Is.EqualTo(3), $"The Authorize was answered with an error: {frame}");

                station.Abort();

                return (JObject) frame[2]!["idTokenInfo"]!;

            }

        }

        #endregion


        #region ACardIsWhatItsPartnerSaysItIs()

        /// <summary>
        /// A card charges where a partner sent it, calls it valid and lets this
        /// operator decide on it - and is turned away with the reason
        /// otherwise.
        /// </summary>
        [Test]
        public void ACardIsWhatItsPartnerSaysItIs()
        {

            var valid    = CSMS.AuthorizationOf(AValidCard);
            var lower    = CSMS.AuthorizationOf(AValidCard.ToLowerInvariant());
            var notValid = CSMS.AuthorizationOf(NotValid);
            var never    = CSMS.AuthorizationOf(AskedOfItsPartner);
            var nobodys  = CSMS.AuthorizationOf(NobodysCard);

            Assert.Multiple(() => {

                Assert.That(valid.   Status,   Is.EqualTo(AuthorizationStatus.Accepted));
                Assert.That(valid.   Partner,  Is.EqualTo("DE*GDF"));
                Assert.That(lower.   Status,   Is.EqualTo(AuthorizationStatus.Accepted), "a UID is the same card in lower case");

                Assert.That(notValid.Status,   Is.EqualTo(AuthorizationStatus.Invalid));
                Assert.That(notValid.Partner,  Is.EqualTo("DE*GDF"));

                // Its partner's to decide on when it is used, which this CSMS
                // does not ask yet: not accepted on what was pushed.
                Assert.That(never.   Status,   Is.EqualTo(AuthorizationStatus.Unknown));
                Assert.That(never.   Why,      Does.Contain("NEVER"));

                Assert.That(nobodys. Status,   Is.EqualTo(AuthorizationStatus.Unknown));
                Assert.That(nobodys. Partner,  Is.Null);

            });

        }

        #endregion

        #region TheCardsTheNodeKnowsForTestingAreNobodys(UID)

        /// <summary>
        /// The three cards the OCPP node accepts for testing are no partner's,
        /// and charge nowhere at this CSMS.
        /// </summary>
        [TestCase("3bac1b20")]
        [TestCase("04E77E7318DE")]
        [TestCase("aabbccdd")]
        public async Task TheCardsTheNodeKnowsForTestingAreNobodys(String UID)
        {

            var answered = await AStationAsksAbout(UID);

            Assert.That(answered.Value<String>("status"), Is.EqualTo("Unknown"), answered.ToString());

        }

        #endregion

        #region AStationIsToldWhatThePartnerSaid()

        /// <summary>
        /// Over the wire: a station's Authorize is answered "Accepted" for the
        /// card a partner calls valid, with how long the station may go by
        /// that, and with the reason for the others.
        /// </summary>
        [Test]
        public async Task AStationIsToldWhatThePartnerSaid()
        {

            var valid     = await AStationAsksAbout(AValidCard);
            var notValid  = await AStationAsksAbout(NotValid);
            var nobodys   = await AStationAsksAbout(NobodysCard);

            Assert.Multiple(() => {

                Assert.That(valid.   Value<String>("status"),  Is.EqualTo("Accepted"), valid.ToString());
                Assert.That(notValid.Value<String>("status"),  Is.EqualTo("Invalid"),  notValid.ToString());
                Assert.That(nobodys. Value<String>("status"),  Is.EqualTo("Unknown"),  nobodys.ToString());

                Assert.That(valid["cacheExpiryDateTime"],      Is.Not.Null, "The station is not told how long the answer holds.");

            });

            // What the log says of the three questions: who the card is of,
            // why it was turned away - and its last four characters only.
            var said = CSMS.Log.Recent(200).
                            Select(entry => entry.Message).
                            Where (message => message.StartsWith("The card ", StringComparison.Ordinal)).
                            ToArray();

            Assert.Multiple(() => {
                Assert.That(said.Length,  Is.EqualTo(3));
                Assert.That(said,         Has.Some.Contains("was accepted").And.Contains("DE*GDF"));
                Assert.That(said,         Has.Some.Contains("was turned away (Invalid)"));
                Assert.That(said,         Has.Some.Contains("was turned away (Unknown)"));
                Assert.That(said,         Has.None.Contains(AValidCard), "The authorization log says a card's whole UID.");
            });

        }

        #endregion

    }

}
