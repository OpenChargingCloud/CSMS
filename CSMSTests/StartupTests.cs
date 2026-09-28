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

using cloud.charging.open.CSMS.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What a CSMS does with the configuration file it is handed
    /// and the accounts it finds, and what it refuses to do.
    /// </summary>
    /// <remarks>
    /// The configuration is read in the constructor, so those tests only build
    /// a CSMS. What every node's start does - the first account and its
    /// hash, a second start that makes up nothing, a file that cannot be read,
    /// the clock set before anything asks it - is asked in WWCP_Node_Tests,
    /// once for every kind of node; what is here is the CSMS's own.
    /// </remarks>
    public class StartupTests
    {

        #region Data

        private String directory = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
        {
            directory = TestCSMSs.TemporaryDirectory("startup");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
            => TestCSMSs.Remove(directory);

        #endregion


        #region ACSMSWithNoFilesIsTheDefaultOCPPNode()

        /// <summary>
        /// Nobody wrote down who this CSMS is in OCPP, so it is the one the
        /// defaults describe.
        /// </summary>
        [Test]
        public async Task ACSMSWithNoFilesIsTheDefaultOCPPNode()
        {

            await using var CSMS = TestCSMSs.New(directory);

            Assert.Multiple(() => {
                Assert.That(CSMS.Node.Id.ToString(),   Is.EqualTo(OCPPConfiguration.DefaultNodeId));
                Assert.That(CSMS.Node.VendorName,      Is.EqualTo(OCPPConfiguration.DefaultVendorName));
            });

        }

        #endregion

        #region TheFileDecidesWhoThisCSMSIsInOCPP()

        /// <summary>
        /// Read once, at the start. What the file says beats what the
        /// constructor was handed, and what it does not mention is left alone.
        /// </summary>
        [Test]
        public async Task TheFileDecidesWhoThisCSMSIsInOCPP()
        {

            var configuration = new JObject(
                                    new JProperty("nts",  new JObject(new JProperty("enabled", false))),
                                    new JProperty("ocpp", new JObject(
                                        new JProperty("nodeId",      "lc-in-the-file"),
                                        new JProperty("vendorName",  "Somebody Else")
                                    ))
                                );

            await using var CSMS = TestCSMSs.New(directory, configuration);

            Assert.Multiple(() => {
                Assert.That(CSMS.Node.Id.ToString(),  Is.EqualTo("lc-in-the-file"));
                Assert.That(CSMS.Node.VendorName,     Is.EqualTo("Somebody Else"));
                // Not mentioned, so the default stands.
                Assert.That(CSMS.Node.Model,          Is.EqualTo(OCPPConfiguration.DefaultModel));
            });

        }

        #endregion

    }

}
