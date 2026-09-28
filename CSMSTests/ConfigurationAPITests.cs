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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What this CSMS says it is, beyond what every node says of itself.
    /// </summary>
    /// <remarks>
    /// What every node says, and what happens when somebody tells it to
    /// resolve names or keep time otherwise, is asked of every kind by the
    /// conformance suite of WWCP_Node_TestKit - see CSMSConformance.
    /// </remarks>
    public class ConfigurationAPITests : ACSMSTests
    {

        #region TheStatusSaysWhoThisCSMSIsInOCPP()

        /// <summary>
        /// What a CSMS's status says beyond every node's - see the conformance
        /// suite of WWCP_Node_TestKit for that: its identity in OCPP, right
        /// after the version.
        /// </summary>
        [Test]
        public async Task TheStatusSaysWhoThisCSMSIsInOCPP()
        {

            using var http = await SignedIn();

            var status = await GetJSON(http, "/api/v1/status");

            Assert.Multiple(() => {
                Assert.That(status.Value<String>("service"),  Is.EqualTo("CSMS"));
                Assert.That(status.Value<String>("ocppId"),   Is.EqualTo(CSMS.Node.Id.ToString()));
                Assert.That(status.Properties().Select(property => property.Name).Take(3),
                            Is.EqualTo(new[] { "service", "version", "ocppId" }));
            });

        }

        #endregion

        #region TheConfigurationNamesEverySection()

        /// <summary>
        /// The Configuration page renders whatever the CSMS sends rather
        /// than a list of its own, so a section going missing is not a broken
        /// page - it is a page that quietly stops mentioning something.
        /// </summary>
        [Test]
        public async Task TheConfigurationNamesEverySection()
        {

            using var http = await SignedIn();

            var configuration = await GetJSON(http, "/api/v1/configuration");

            // The node's own sections - http, web, log and time - are asked
            // of every kind by the conformance suite of WWCP_Node_TestKit.
            Assert.Multiple(() => {
                Assert.That(configuration["CSMS"],       Is.Not.Null);
                Assert.That(configuration["ocpp"],       Is.Not.Null);
                Assert.That(configuration["assemblies"], Is.TypeOf<JArray>());
            });

        }

        #endregion

        #region TheOCPPSectionDescribesTheNode()

        [Test]
        public async Task TheOCPPSectionDescribesTheNode()
        {

            using var http = await SignedIn();

            var ocpp = (await GetJSON(http, "/api/v1/configuration"))["ocpp"];

            Assert.Multiple(() => {
                Assert.That(ocpp?.Value<String>("version"),  Is.EqualTo("2.1"));
                Assert.That(ocpp?.Value<String>("role"),     Is.EqualTo("CSMS"));
                Assert.That(ocpp?.Value<String>("id"),       Is.EqualTo(CSMS.Node.Id.ToString()));
                Assert.That(ocpp?.Value<String>("vendor"),   Is.EqualTo(CSMS.Node.VendorName));
                Assert.That(ocpp?.Value<String>("model"),    Is.EqualTo(CSMS.Node.Model));
            });

        }

        #endregion


        #region TheNTSConfigurationIsReadable()

        [Test]
        public async Task TheNTSConfigurationIsReadable()
        {

            using var http = await SignedIn();

            var nts = await GetJSON(http, "/api/v1/configuration/nts");

            Assert.Multiple(() => {
                // Switched off by the fixture, so that no test reaches the
                // network - the servers it would ask are still named, below,
                // and so is what they are held to.
                Assert.That(nts.Value<Boolean>("enabled"),                Is.False);
                Assert.That(nts["settings"]?.Value<Int32>("minServers"),  Is.EqualTo(2));
                Assert.That(nts.Value<String>("file"),                    Is.EqualTo(CSMS.ConfigFile.Path));

                // What the page draws its "Time servers" card from. A CSMS
                // nobody has configured asks the PTB's four, so the card has
                // four to draw rather than nothing.
                Assert.That(nts["timeSources"],                           Is.Not.Null.And.Count.EqualTo(4));
                Assert.That(nts["timeSources"]?[0]?.Value<String>("hostname"),
                                                                          Is.EqualTo(CSMS.NTSClient.Hostname.ToString()));
                Assert.That(nts["group"]?.Value<String>("name"),          Is.EqualTo("legal"));
                Assert.That(nts["group"]?.Value<Byte>  ("minServers"),    Is.EqualTo(2));
            });

        }

        #endregion

        #region OneTimeServerCanBeTestedFromThePage()

        /// <summary>
        /// The NTS page tests each server of the group from its own row, and
        /// the log says who asked for which - in the words the page sends, the
        /// name as it is read.
        /// </summary>
        /// <remarks>
        /// NTS is switched off by the fixture, so the test answers that nothing
        /// was asked, and nothing goes out.
        /// </remarks>
        [Test]
        public async Task OneTimeServerCanBeTestedFromThePage()
        {

            using var http = await SignedIn();

            var before   = CSMS.Log.LastId;

            var response = await http.PostAsync("/api/v1/configuration/nts/test",
                                                JSONBody(new JProperty("host", "ptbtime2.ptb.de")));

            var body     = await response.Content.ReadAsStringAsync();
            var said     = CSMS.Log.Recent(20, before, "nts").Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                         Is.EqualTo(HttpStatusCode.OK),  body);
                Assert.That(response.IsSuccessStatusCode ? JObject.Parse(body)["steps"] : null,  Is.Not.Null);
                Assert.That(said,  Has.Some.EqualTo($"'{CSMS.DefaultAdminUser}' asked this CSMS to test the time server 'ptbtime2.ptb.de'."),
                            String.Join(" | ", said));
            });

        }

        #endregion

    }

}
