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

using NUnit.Framework;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// Which commits the banner says this CSMS is running.
    /// </summary>
    public class BuiltFromTests
    {

        #region TwoRepositoriesOfOneNameAreBothReported()

        /// <summary>
        /// A repository is named after the directory it was cloned into, so two
        /// of them can share a name - found in the energy meter, where the
        /// command line tool and its library are both checked out as
        /// "ModbusTLSEnergyMeter". On the name alone they were one line, and the
        /// other one's commit was dropped without a word.
        /// </summary>
        [Test]
        public void TwoRepositoriesOfOneNameAreBothReported()
        {

            var lines = BuiltFrom.RepositoriesOf([
                            new LoadedAssembly("ModbusTLSEnergyMeterCLI",  "1.0.0",  "ModbusTLSEnergyMeter",  "1111111111111111111111111111111111111111"),
                            new LoadedAssembly("ModbusTLSEnergyMeter",     "1.0.0",  "ModbusTLSEnergyMeter",  "2222222222222222222222222222222222222222"),
                            new LoadedAssembly("WWCP_ISO15118_2",          "1.0.0",  "WWCP_ISO15118",         "3333333333333333333333333333333333333333"),
                            new LoadedAssembly("WWCP_ISO15118_EXI",        "1.0.0",  "WWCP_ISO15118",         "3333333333333333333333333333333333333333"),
                            new LoadedAssembly("Newtonsoft.Json",          "13.0.0", null,                    null)
                        ]).
                        Select(line => $"{line.Repository} {line.Commit![..4]}").
                        ToArray();

            // And the case the grouping exists for still collapses: many
            // assemblies out of one repository are one line.
            Assert.That(lines,  Is.EqualTo(new[] {
                                    "ModbusTLSEnergyMeter 1111",
                                    "ModbusTLSEnergyMeter 2222",
                                    "WWCP_ISO15118 3333"
                                }));

        }

        #endregion

    }

}
