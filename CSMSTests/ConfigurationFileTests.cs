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
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The file a CSMS writes itself down in.
    /// </summary>
    /// <remarks>
    /// What the file does for every node - an empty one, a broken one, a
    /// section merged or replaced, one it does not know kept - is asked in
    /// WWCP_Node_Tests, once for every kind of node. What is here is the
    /// CSMS's own section beside the node's.
    /// </remarks>
    public class ConfigurationFileTests
    {

        #region Data

        private String                directory   = default!;
        private WWCPConfigFile  file        = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeAFile()
        {
            directory = TestCSMSs.TemporaryDirectory("config");
            Directory.CreateDirectory(directory);
            file      = new WWCPConfigFile(Path.Combine(directory, "configuration.json"));
        }

        [TearDown]
        public void RemoveTheDirectory()
            => TestCSMSs.Remove(directory);

        #endregion


        #region TheCSMSsSectionComesBackBesideTheNodes()

        /// <summary>
        /// One file with the sections of the node below and those of the CSMS
        /// in it, and each read back by whoever it belongs to.
        /// </summary>
        /// <remarks>
        /// One file with two readers: the sections every node has, which the
        /// node below reads, and the CSMS's own, read from the same document.
        /// Neither is lost to the other.
        /// </remarks>
        [Test]
        public void TheCSMSsSectionComesBackBesideTheNodes()
        {

            var written = new WWCPConfiguration(
                              DNS:   new DNSConfiguration(Enabled: false),
                              NTS:   new NTSConfiguration(Enabled: true)
                          ).ToJSON();

            written.Merge(new CSMSConfiguration(
                              OCPP:  new OCPPConfiguration(NodeId: "lc042", VendorName: "ACME")
                          ).ToJSON());

            file.TryWrite(written, out _);

            Assert.That(file.TryLoad(out var read, out var error), Is.True, error);
            Assert.That(file.TryLoadDocument(out var document, out var problem), Is.True, problem);
            Assert.That(CSMSConfiguration.TryParse(document!, out var csms, out var csmsError), Is.True, csmsError);

            Assert.Multiple(() => {
                Assert.That(read!.DNS?.Enabled,        Is.False);
                Assert.That(read.NTS?.Enabled,         Is.True);
                Assert.That(read.IsEmpty,              Is.False);
                Assert.That(csms!.OCPP?.NodeId,        Is.EqualTo("lc042"));
                Assert.That(csms.OCPP?.VendorName,     Is.EqualTo("ACME"));
                Assert.That(csms.IsEmpty,              Is.False);
            });

        }

        #endregion

    }

}
