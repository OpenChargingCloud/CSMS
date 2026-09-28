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


    }

}
