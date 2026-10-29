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

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    #region (static) OCPIStrangers

    /// <summary>
    /// What both fixtures below ask with: a CSMS speaking every OCPI version,
    /// a caller with a token nobody gave it, and the answer it gets.
    /// </summary>
    internal static class OCPIStrangers
    {

        public const String UnknownAccessToken = "Unknown access token!";

        public static JObject EveryVersion(Boolean OpenData)
        {

            var configuration = TestCSMSs.LoopbackPartners(TestCSMSs.Offline);
            var ocpi          = (JObject) configuration["ocpi"]!;

            ocpi["versions"] = new JArray("2.1.1", "2.2.1", "2.3.0");

            if (OpenData)
            {
                ocpi["locationsAsOpenData"] = true;
                ocpi["tariffsAsOpenData"]   = true;
            }

            return configuration;

        }

        /// <summary>
        /// A caller with a token, or none.
        /// </summary>
        public static HttpClient Caller(String BaseURL, String? Token)
        {

            var http = new HttpClient { BaseAddress = new Uri(BaseURL) };

            if (Token is not null)
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                               "Token",
                                                               Convert.ToBase64String(Encoding.UTF8.GetBytes(Token))
                                                           );

            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return http;

        }

        public static async Task<(HttpStatusCode Status, JObject Answer, String Text)> Get(HttpClient HTTP, String Path)
        {

            var response = await HTTP.GetAsync(Path);
            var text     = await response.Content.ReadAsStringAsync();

            return (response.StatusCode, JObject.Parse(text), text);

        }

        /// <summary>
        /// 401, OCPI 2000, "Unknown access token!" - and nothing of what is
        /// behind the path.
        /// </summary>
        public static async Task AssertRefused(HttpClient HTTP, String Path)
        {

            var (status, answer, text) = await Get(HTTP, Path);

            Assert.Multiple(() => {
                Assert.That(status,                                Is.EqualTo(HttpStatusCode.Unauthorized),  $"GET {Path} with a made-up token was answered {(Int32) status}: {text}");
                Assert.That(answer.Value<Int32> ("status_code"),     Is.EqualTo(2000),                         $"GET {Path}: {text}");
                Assert.That(answer.Value<String>("status_message"),  Is.EqualTo(UnknownAccessToken),           $"GET {Path}: {text}");
                Assert.That(answer.ContainsKey("data"),              Is.False,                                 $"GET {Path} with a made-up token was given data: {text}");
            });

        }

    }

    #endregion


    /// <summary>
    /// A token nobody here gave out is refused at every path of every OCPI
    /// version this CSMS speaks, before the path is asked: 401 and why, the
    /// same everywhere - not the version details of a partner, and not an
    /// endpoint that would have to refuse it itself.
    /// </summary>
    /// <remarks>
    /// Before WWCP_OCPI 0b7483b6 only 2.3.0 and the versions list did; the
    /// version details of 2.1.1 and 2.2.1 answered a made-up token 1000.
    /// </remarks>
    public class OCPITokenRefusalTests : ACSMSTests
    {

        protected override JObject Configuration
            => OCPIStrangers.EveryVersion(OpenData: false);


        #region AMadeUpTokenIsRefusedBeforeEveryPath(Version)

        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task AMadeUpTokenIsRefusedBeforeEveryPath(String Version)
        {

            using var stranger = OCPIStrangers.Caller(BaseURL, "nobody-gave-me-this");

            foreach (var path in new[] {
                                     "/ext/versions",
                                     $"/ext/versions/{Version}",
                                     $"/ext/v{Version}/credentials",
                                     $"/ext/v{Version}/cpo/locations",
                                     $"/ext/v{Version}/cpo/tariffs"
                                 })
                await OCPIStrangers.AssertRefused(stranger, path);

        }

        #endregion

        #region WithoutATokenTheVersionsAreStillOpen(Version)

        /// <summary>
        /// No token is not a made-up one: an EMSP that has not registered yet
        /// still finds the credentials endpoint.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task WithoutATokenTheVersionsAreStillOpen(String Version)
        {

            using var nobody = OCPIStrangers.Caller(BaseURL, null);

            var (status, answer, text) = await OCPIStrangers.Get(nobody, $"/ext/versions/{Version}");

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), text);

            var identifiers = (answer["data"]?["endpoints"] as JArray)?.Select(endpoint => endpoint.Value<String>("identifier")).ToArray();

            Assert.That(identifiers, Does.Contain("credentials"), text);

        }

        #endregion

    }


    /// <summary>
    /// With "locationsAsOpenData" and "tariffsAsOpenData" the locations and
    /// tariffs are anybody's - a made-up token reads them as no token does -
    /// and nothing else is: the versions, the version details and the
    /// credentials still refuse a made-up token.
    /// </summary>
    /// <remarks>
    /// Before WWCP_OCPI 0b7483b6 open locations took a made-up token as
    /// nobody's at every path, the versions list included.
    /// </remarks>
    public class OCPIOpenDataTokenTests : ACSMSTests
    {

        protected override JObject Configuration
            => OCPIStrangers.EveryVersion(OpenData: true);


        #region AMadeUpTokenReadsOpenDataAsNobodyDoes(Version)

        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task AMadeUpTokenReadsOpenDataAsNobodyDoes(String Version)
        {

            using var stranger = OCPIStrangers.Caller(BaseURL, "nobody-gave-me-this");
            using var nobody   = OCPIStrangers.Caller(BaseURL, null);

            foreach (var (who, http) in new[] { ("A made-up token", stranger), ("No token", nobody) })
                foreach (var path in new[] { $"/ext/v{Version}/cpo/locations", $"/ext/v{Version}/cpo/tariffs" })
                {

                    var (status, answer, text) = await OCPIStrangers.Get(http, path);

                    Assert.Multiple(() => {
                        Assert.That(status,                               Is.EqualTo(HttpStatusCode.OK),  $"{who} at {path} was answered {(Int32) status}: {text}");
                        Assert.That(answer.Value<Int32>("status_code"),   Is.EqualTo(1000),               $"{who} at {path}: {text}");
                        Assert.That(answer["data"],                       Is.InstanceOf<JArray>(),        $"{who} at {path}: {text}");
                    });

                }

        }

        #endregion

        #region OpenDataOpensNothingElse(Version)

        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task OpenDataOpensNothingElse(String Version)
        {

            using var stranger = OCPIStrangers.Caller(BaseURL, "nobody-gave-me-this");

            foreach (var path in new[] {
                                     "/ext/versions",
                                     $"/ext/versions/{Version}",
                                     $"/ext/v{Version}/credentials"
                                 })
                await OCPIStrangers.AssertRefused(stranger, path);

            if (Version == "2.1.1")
                await OCPIStrangers.AssertRefused(stranger, "/ext/v2.1.1/cpo/sessions");

        }

        #endregion

    }

}
