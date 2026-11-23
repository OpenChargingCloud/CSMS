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
    /// Where the CSRs of the stations go: an EST server - or a connection of
    /// the CSMS to its PKI, with the label of EST after its '#'.
    /// </summary>
    public class CertificateSigningConfigurationTests
    {

        private static Boolean Parse(String Address, out CertificateSigningConfiguration? Configuration, out String? Error)

            => CertificateSigningConfiguration.TryParse(new JObject(new JProperty("chargingStationCertificate", Address)), out Configuration, out Error);


        [TestCase("ws://127.0.0.1:2364/csms-01#stations",   "ws://127.0.0.1:2364/csms-01",   "stations")]
        [TestCase("wss://pki.example.org:2364/csms-01#a_b", "wss://pki.example.org:2364/csms-01", "a_b")]
        [TestCase("ssh://csms-01@pki.example.org:22#secc",  "ssh://csms-01@pki.example.org:22",   "secc")]
        [TestCase("wss://pki.example.org:2364/csms-01",     "wss://pki.example.org:2364/csms-01", null)]
        public void AConnection_IsKeptWithItsLabel(String Address, String URL, String? Label)
        {

            Assert.That(Parse(Address, out var configuration, out var error), Is.True, error);

            var address = configuration!.ChargingStationCertificate!;

            Assert.Multiple(() => {
                Assert.That(CertificateSigningConfiguration.IsConnection   (address),  Is.True);
                Assert.That(CertificateSigningConfiguration.ConnectionURLOf(address),  Is.EqualTo(URL));
                Assert.That(CertificateSigningConfiguration.LabelOf        (address),  Is.EqualTo(Label));
                Assert.That(configuration.ToJSON()["chargingStationCertificate"]?.Value<String>(), Is.EqualTo(Address), "written back as it was given");
                Assert.That(configuration.MayAsk(new Uri("http://pki.example.org/ocsp")), Is.False, "the host of a connection names no OCSP responder");
            });

        }

        [TestCase("wss://pki.example.org:2364/csms-01#no labels")]
        [TestCase("wss://pki.example.org:2364/csms-01?x=1#stations")]
        [TestCase("https://pki.example.org/.well-known/est#stations")]
        [TestCase("ftp://pki.example.org/")]
        public void WhatIsNoAddress_IsRefused(String Address)
        {
            Assert.That(Parse(Address, out _, out var error), Is.False);
            Assert.That(error, Is.Not.Null);
        }

        [Test]
        public void AnESTServer_IsAsItWas()
        {

            Assert.That(Parse("https://pki.example.org/.well-known/est/stations/", out var configuration, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(configuration!.ChargingStationCertificate!.ToString(),                       Is.EqualTo("https://pki.example.org/.well-known/est/stations"));
                Assert.That(CertificateSigningConfiguration.IsConnection(configuration.ChargingStationCertificate!), Is.False);
                Assert.That(configuration.MayAsk(new Uri("http://pki.example.org/ocsp")),               Is.True);
            });

        }

    }

}
