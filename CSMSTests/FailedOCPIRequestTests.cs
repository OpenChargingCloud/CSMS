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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.OCPI;
using cloud.charging.open.protocols.WWCP.Node.Logging;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// An OCPI request whose handling throws: its caller is told no more than
    /// the ids to quote, and the log of this CSMS says what was asked, by whom
    /// and what was thrown - not the token it came with.
    /// </summary>
    /// <remarks>
    /// The OCPI library answers such a request itself, and says what was
    /// thrown to nobody but CommonHTTPAPI.OnRequestFailed. What throws here is
    /// a route of the tests' own on this CSMS's Common HTTP API, beside the
    /// versions list and under the same prefix: nothing of this CSMS throws
    /// on purpose.
    ///
    /// And a Basic authentication whose password is no TOTP, which is what
    /// every scanner sends and which made reading the request throw before
    /// WWCP_OCPI d013cce8, is not a failure at all.
    /// </remarks>
    public class FailedOCPIRequestTests : ACSMSTests
    {

        #region Data

        private const String Marker         = "C0FFEE-only-the-log-may-know-this";
        private const String RequestId      = "a-request-id-of-the-caller";
        private const String CorrelationId  = "a-correlation-id-of-the-caller";

        #endregion

        #region (private) Throwing()

        /// <summary>
        /// A route on this CSMS's Common HTTP API whose handler throws, and the
        /// URL it is reached at.
        /// </summary>
        private String Throwing()
        {

            CSMS.OCPIAPI.AddOCPIMethod(
                HTTPMethod.GET,
                CSMS.OCPIAPI.URLPathPrefix + "throws",
                request => throw new InvalidOperationException(Marker)
            );

            var versionsURL = CSMS.OCPIVersionsURL.ToString();

            return versionsURL[..^"versions".Length] + "throws";

        }

        #endregion

        #region (private) Send(URL, Authorization)

        /// <summary>
        /// A GET with the request and correlation ids a caller would quote.
        /// </summary>
        private static async Task<(HttpResponseMessage Response, String Text)> Send(String                      URL,
                                                                                    AuthenticationHeaderValue?  Authorization)
        {

            using var http     = new HttpClient();
            using var request  = new HttpRequestMessage(HttpMethod.Get, URL);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("X-Request-ID",      RequestId);
            request.Headers.Add("X-Correlation-ID",  CorrelationId);

            if (Authorization is not null)
                request.Headers.Authorization = Authorization;

            var response = await http.SendAsync(request);

            return (response, await response.Content.ReadAsStringAsync());

        }

        #endregion

        #region (private static) Token(Token) / Basic(User, Password)

        private static AuthenticationHeaderValue Token(String Token)

            => new ("Token", Convert.ToBase64String(Encoding.UTF8.GetBytes(Token)));

        private static AuthenticationHeaderValue Basic(String User, String Password)

            => new ("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{User}:{Password}")));

        #endregion

        #region (private) Failures()

        /// <summary>
        /// What the log of this CSMS says about failed OCPI requests.
        /// </summary>
        private LogEntry[] Failures()

            => [.. CSMS.Log.Recent(500, Tag: "http").Where(entry => entry.Tags.Contains("ocpi") && entry.Level == LogLevel.Error)];

        #endregion

        #region (private) AddPartner(Admin)

        /// <summary>
        /// A roaming partner added through the JSON API, and the token this
        /// operator made up for it.
        /// </summary>
        private static async Task<(String Id, String Token)> AddPartner(HttpClient Admin)
        {

            var response = await Admin.PostAsync("/api/v1/ocpi/partners", JSONBody(
                                                                               new JProperty("version",      "2.2.1"),
                                                                               new JProperty("countryCode",  "DE"),
                                                                               new JProperty("partyId",      "GDF"),
                                                                               new JProperty("role",         "EMSP"),
                                                                               new JProperty("name",         "Test EMSP")
                                                                           ));

            var text     = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created), $"Adding the partner answered {(Int32) response.StatusCode}: {text}");

            var answer   = JObject.Parse(text);

            return (answer.Value<String>("id")!, answer.Value<String>("ourToken")!);

        }

        #endregion


        #region AFailedRequestTellsItsCallerNoMoreThanItsIds()

        /// <summary>
        /// OCPI 3000 with HTTP 500, a message that says nothing of this CSMS,
        /// and the ids the caller came with - not what was thrown, nor where
        /// this CSMS was built.
        /// </summary>
        [Test]
        public async Task AFailedRequestTellsItsCallerNoMoreThanItsIds()
        {

            var (response, text) = await Send(Throwing(), Authorization: null);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);

            var answer  = JObject.Parse(text);
            var header  = response.Headers.TryGetValues("X-Request-ID", out var ids) ? ids.Single() : null;

            Assert.Multiple(() => {
                Assert.That(answer.Value<Int32> ("status_code"),     Is.EqualTo(3000),                                     text);
                Assert.That(answer.Value<String>("status_message"),  Is.EqualTo(CommonHTTPAPI.FailedRequestMessage),       text);
                Assert.That(answer.Value<String>("requestId"),       Is.EqualTo(RequestId),                                "The caller is not given the request id to quote.");
                Assert.That(answer.Value<String>("correlationId"),   Is.EqualTo(CorrelationId),                            "The caller is not given the correlation id to quote.");
                Assert.That(header,                                  Is.EqualTo(RequestId),                                "The request id is not among the headers.");
                Assert.That(text,                                    Does.Not.Contain(Marker),                             "The caller is told what was thrown.");
                Assert.That(text,                                    Does.Not.Contain(nameof(InvalidOperationException)),  "The caller is told what was thrown.");
                Assert.That(text,                                    Does.Not.Contain(".cs:line"),                         "The caller is told where this CSMS was built.");
            });

        }

        #endregion

        #region AFailedRequestIsAnErrorInTheLog()

        /// <summary>
        /// What the caller is not told is in the log: what was asked, from
        /// where, the ids the caller was given, and what was thrown.
        /// </summary>
        [Test]
        public async Task AFailedRequestIsAnErrorInTheLog()
        {

            var url               = Throwing();
            var (response, text)  = await Send(url, Authorization: null);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);

            var said = Failures();

            Assert.That(said, Has.Length.EqualTo(1), "The request that failed is not in the log, or more than once.");

            Assert.Multiple(() => {
                Assert.That(said[0].Message,                           Does.Contain($"GET {new Uri(url).AbsolutePath}"),  "The log does not say what was asked.");
                Assert.That(said[0].Message,                           Does.Contain("somebody at "),                     "The log does not say where it came from.");
                Assert.That(said[0].Message,                           Does.Contain(RequestId),                          "The log does not say the request id the caller was given.");
                Assert.That(said[0].Message,                           Does.Contain(CorrelationId),                      "The log does not say the correlation id the caller was given.");
                Assert.That(said[0].Message,                           Does.Contain(Marker),                             "The log does not say what was thrown.");
                Assert.That(said[0].Data?.Value<String>("exception"),  Is.EqualTo(typeof(InvalidOperationException).FullName));
            });

        }

        #endregion

        #region AFailedRequestOfAPartnerNamesThePartnerAndNotItsToken()

        /// <summary>
        /// A request whose token is known names the partner who sent it - and
        /// not the token, nor anything else of its headers.
        /// </summary>
        [Test]
        public async Task AFailedRequestOfAPartnerNamesThePartnerAndNotItsToken()
        {

            using var admin       = await SignedIn();

            var (id, token)       = await AddPartner(admin);
            var authorization     = Token(token);

            var (response, text)  = await Send(Throwing(), authorization);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);

            var said = Failures();

            Assert.That(said, Has.Length.EqualTo(1), "The request that failed is not in the log, or more than once.");

            Assert.Multiple(() => {
                Assert.That(said[0].Message,  Does.Contain($"'{id}'"),                    "The log does not say which partner sent the request.");
                Assert.That(said[0].Message,  Does.Not.Contain("somebody at "),           "A partner whose token is known is said to be somebody.");
                Assert.That(said[0].Message,  Does.Not.Contain(token),                    "The token is in the log.");
                Assert.That(said[0].Message,  Does.Not.Contain(authorization.Parameter!),  "The token is in the log, as it was sent.");
            });

        }

        #endregion

        #region ABasicPasswordThatIsNoTOTPIsNoServerError()

        /// <summary>
        /// A Basic authentication whose password is no TOTP - "y" in <c>curl -u
        /// x:y</c>, or none at all - is no failure: the caller is turned away as
        /// an unknown token, and the log has no error to say about it.
        /// </summary>
        [TestCase("y")]
        [TestCase("")]
        public async Task ABasicPasswordThatIsNoTOTPIsNoServerError(String Password)
        {

            var (response, text) = await Send(CSMS.OCPIVersionsURL.ToString(), Basic("x", Password));

            Assert.Multiple(() => {
                Assert.That((Int32) response.StatusCode,  Is.LessThan(500),               $"A scanner was answered {(Int32) response.StatusCode}: {text}");
                Assert.That(response.IsSuccessStatusCode,  Is.False,                      "A made-up token was let in.");
                Assert.That(text,                          Does.Not.Contain(".cs:line"),  "The caller is told where this CSMS was built.");
                Assert.That(Failures(),                    Is.Empty,                      "A scanner is an error in the log.");
            });

        }

        #endregion

        #region APartnersTokenAsTheUserOfABasicAuthenticationLetsItIn()

        /// <summary>
        /// A client that puts its token into the user of a Basic authentication
        /// and leaves the password empty is let in like any other.
        /// </summary>
        [Test]
        public async Task APartnersTokenAsTheUserOfABasicAuthenticationLetsItIn()
        {

            using var admin       = await SignedIn();

            var (_, token)        = await AddPartner(admin);

            var (response, text)  = await Send(CSMS.OCPIVersionsURL.ToString(), Basic(token, ""));

            Assert.That(response.IsSuccessStatusCode, Is.True, $"The partner was answered {(Int32) response.StatusCode}: {text}");

            Assert.Multiple(() => {
                Assert.That(JObject.Parse(text).Value<Int32>("status_code"),  Is.EqualTo(1000),  text);
                Assert.That(Failures(),                                       Is.Empty,          "A partner let in is an error in the log.");
            });

        }

        #endregion

    }

}
