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

using cloud.charging.open.CSMS.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// Where this CSMS calls its roaming partners: on the public internet, and
    /// on another network only where "ocpi.remoteNetworks" allows it.
    /// </summary>
    /// <remarks>
    /// That the OCPI clients keep to it is the libraries' to test, and the
    /// over-the-wire half is in OCPITests; this is the section and the rules
    /// it makes.
    /// </remarks>
    public class RemoteNetworkTests
    {

        #region (private static) Section(Rules)

        private static OCPIConfiguration Section(params String[] Rules)
        {

            Assert.That(OCPIConfiguration.TryParse(new JObject(new JProperty("remoteNetworks", new JArray(Rules))), out var section, out var error),
                        Is.True, error);

            return section!;

        }

        #endregion

        #region (private static) Allows(Section, Address)

        private static Boolean Allows(OCPIConfiguration Section, String Address)

            => Section.RemoteNetworkAcl().Allows(IPAddress.Parse(Address), 443);

        #endregion


        #region SaidNothingThePublicInternetAlone()

        /// <summary>
        /// A section that says nothing: the public internet, and not this
        /// machine, the networks beside it or a cloud's metadata service.
        /// </summary>
        [TestCase("192.0.2.1",       false, Description = "documentation")]
        [TestCase("8.8.8.8",         true)]
        [TestCase("2001:4860::8888", true)]
        [TestCase("127.0.0.1",       false)]
        [TestCase("::1",             false)]
        [TestCase("10.1.2.3",        false)]
        [TestCase("192.168.178.1",   false)]
        [TestCase("169.254.169.254", false, Description = "a cloud's metadata service")]
        [TestCase("fd00::2",         false)]
        [TestCase("::ffff:10.1.2.3", false, Description = "an IPv4 address of a private network, written as IPv6")]
        public void SaidNothingThePublicInternetAlone(String Address, Boolean Allowed)
        {
            Assert.That(Allows(new OCPIConfiguration(), Address), Is.EqualTo(Allowed));
        }

        #endregion

        #region ARuleAllowsANetworkAndNoOther()

        /// <summary>
        /// A rule allowing a network allows it, and leaves every other
        /// non-public one refused.
        /// </summary>
        [Test]
        public void ARuleAllowsANetworkAndNoOther()
        {

            var section = Section("192.168.0.0/16 => ALLOW");

            Assert.Multiple(() => {
                Assert.That(Allows(section, "192.168.178.20"), Is.True);
                Assert.That(Allows(section, "10.1.2.3"),       Is.False);
                Assert.That(Allows(section, "127.0.0.1"),      Is.False);
                Assert.That(Allows(section, "8.8.8.8"),        Is.True);
            });

        }

        #endregion

        #region TheFirstRuleThatMatchesDecides()

        /// <summary>
        /// The rules are read in their order: a host refused before its network
        /// is allowed stays refused, and a public address may be refused too.
        /// </summary>
        [Test]
        public void TheFirstRuleThatMatchesDecides()
        {

            var section = Section("192.168.1.1 => DENY", "192.168.0.0/16 => ALLOW", "203.0.113.0/24 => DENY", "8.8.8.0/24 => DENY");

            Assert.Multiple(() => {
                Assert.That(Allows(section, "192.168.1.1"),  Is.False);
                Assert.That(Allows(section, "192.168.1.2"),  Is.True);
                Assert.That(Allows(section, "8.8.8.8"),      Is.False);
                Assert.That(Allows(section, "8.8.4.4"),      Is.True);
            });

        }

        #endregion

        #region AnythingAllowedSwitchesItOff()

        /// <summary>
        /// Both whole address spaces allowed: anything, as before.
        /// </summary>
        [Test]
        public void AnythingAllowedSwitchesItOff()
        {

            var section = Section("0.0.0.0/0 => ALLOW", "::/0 => ALLOW");

            Assert.Multiple(() => {
                Assert.That(Allows(section, "127.0.0.1"),  Is.True);
                Assert.That(Allows(section, "::1"),        Is.True);
                Assert.That(Allows(section, "10.1.2.3"),   Is.True);
            });

        }

        #endregion

        #region ARuleThatIsNoneIsRefused()

        /// <summary>
        /// What is no rule is the section's error, naming it, rather than a
        /// rule quietly left out - a network the operator meant to refuse would
        /// otherwise be one this CSMS calls.
        /// </summary>
        [TestCase("192.168.0.0/16")]
        [TestCase("192.168.0.0/16 => MAYBE")]
        [TestCase("somewhere => ALLOW")]
        public void ARuleThatIsNoneIsRefused(String Rule)
        {

            Assert.That(OCPIConfiguration.TryParse(new JObject(new JProperty("remoteNetworks", new JArray(Rule))), out _, out var error), Is.False);

            Assert.That(error, Does.Contain("ocpi.remoteNetworks").And.Contain(Rule));

        }

        #endregion

        #region TheRulesAreWrittenBackAsTheyWereSaid()

        /// <summary>
        /// The section written back keeps the rules, in their order, and a
        /// section that said none writes none.
        /// </summary>
        [Test]
        public void TheRulesAreWrittenBackAsTheyWereSaid()
        {

            Assert.Multiple(() => {
                Assert.That(Section("10.0.0.0/8 => ALLOW", "::1 => ALLOW").ToJSON()["remoteNetworks"]?.Values<String>(),
                            Is.EqualTo(new[] { "10.0.0.0/8 => ALLOW", "::1 => ALLOW" }));
                Assert.That(new OCPIConfiguration().ToJSON().ContainsKey("remoteNetworks"), Is.False);
            });

        }

        #endregion

    }

}
