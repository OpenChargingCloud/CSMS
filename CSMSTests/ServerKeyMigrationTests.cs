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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.OCPP.Node;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The keys a CSMS of before kept for its charging station port in a
    /// directory of their own, ocpp-server-keys, are server identities of the
    /// node's certificate store once it starts again - and the directory is
    /// gone with them.
    /// </summary>
    [TestFixture]
    public class ServerKeyMigrationTests
    {

        #region Data

        private String directory = "";

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
        {
            directory = TestCSMSs.TemporaryDirectory("server-key-migration");
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
        {
            TestCSMSs.Remove(directory);
        }

        #endregion


        #region AKeyWithItsCertificateBecomesAServerIdentity()

        /// <summary>
        /// A key, its signing request, the certificate that answers it and
        /// what was said of it, as a CSMS of before wrote them: one server
        /// identity of the listener "ocpp", which the station port presents.
        /// </summary>
        [Test]
        public async Task AKeyWithItsCertificateBecomesAServerIdentity()
        {

            using var ca   = TestCA.Create($"Test CA {Guid.NewGuid()}");
            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request    = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
            var csr        = request.CreateSigningRequestPem();

            using var certificate = ca.Sign(csr, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

            var keys       = Path.Combine(directory, CSMS.FormerServerKeysDirectoryName);
            var id         = "0123456789abcdef";

            Directory.CreateDirectory(keys);

            File.WriteAllText(Path.Combine(keys, $"{id}.key.pem"),   key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(Path.Combine(keys, $"{id}.csr.pem"),   csr);
            File.WriteAllText(Path.Combine(keys, $"{id}.cert.pem"),  ca.ChainPEM(certificate));
            File.WriteAllText(Path.Combine(keys, $"{id}.json"),      new JObject(
                                                                         new JProperty("algorithm",    "ecdsa-p256"),
                                                                         new JProperty("createdAt",    DateTimeOffset.UtcNow.AddDays(-2).ToString("o")),
                                                                         new JProperty("subject",      "CN=127.0.0.1"),
                                                                         new JProperty("reachableAs",  new JArray("127.0.0.1"))
                                                                     ).ToString());

            await using var csms = TestCSMSs.New(directory, TestCSMSs.Offline);

            var identities = csms.Certificates.UsableFor(CertificateKind.TLSServerIdentity, OCPPServingNode.StationListener);

            Assert.Multiple(() => {

                Assert.That(identities,                                      Has.Count.EqualTo(1),
                            "The server key of before is not a server identity of the station port.");

                Assert.That(csms.StationCertificate.Current?.Certificate.Thumbprint,
                            Is.EqualTo(certificate.Thumbprint),
                            "The station port does not present the certificate of before.");

                Assert.That(Directory.Exists(keys),                          Is.False,
                            "The directory of before is still there, with a private key in two places.");

            });

        }

        #endregion

        #region WhatCannotBeMovedStaysWhereItIs()

        /// <summary>
        /// A key whose signing request is not there cannot be adopted: it stays
        /// where it was, and the directory with it, to be tried again.
        /// </summary>
        [Test]
        public async Task WhatCannotBeMovedStaysWhereItIs()
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var keys = Path.Combine(directory, CSMS.FormerServerKeysDirectoryName);
            var file = Path.Combine(keys, "fedcba9876543210.key.pem");

            Directory.CreateDirectory(keys);
            File.WriteAllText(file, key.ExportPkcs8PrivateKeyPem());

            await using var csms = TestCSMSs.New(directory, TestCSMSs.Offline);

            Assert.Multiple(() => {
                Assert.That(File.Exists(file), Is.True, "A key that could not be moved was taken away.");
                Assert.That(csms.Certificates.UsableFor(CertificateKind.TLSServerIdentity, OCPPServingNode.StationListener), Is.Empty);
            });

        }

        #endregion

    }

}
