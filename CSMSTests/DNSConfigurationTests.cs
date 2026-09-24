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

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.CSMS.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What the "dns" section may say about the name servers - and what it may
    /// not, said as a sentence about the file rather than as an exception.
    /// </summary>
    /// <remarks>
    /// "udp://213.133.98.98:53" is how the log names a name server, and not a
    /// form this section has ever taken - here, or in the vehicle, the charging
    /// station and the energy meter, whose sections it shares so that one file
    /// can be copied between them. A CSMS given it stopped at its start with an
    /// ArgumentException out of Hermod's IPAddress.TryParse, which named neither
    /// the file nor the key. That TryParse says no now, and what is not read is
    /// refused the way any other mistake in the file is.
    /// </remarks>
    public class DNSConfigurationTests
    {

        #region Data

        private String directory = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
            => directory = TestCSMSs.TemporaryDirectory("dns");

        [TearDown]
        public void RemoveTheDirectory()
            => TestCSMSs.Remove(directory);

        #endregion


        #region TheShortFormIsOneNameServerOverUDP()

        /// <summary>
        /// An address and nothing else about it: a name server asked over UDP
        /// on port 53.
        /// </summary>
        [Test]
        public void TheShortFormIsOneNameServerOverUDP()
        {

            var section = JObject.Parse("""{ "enabled": true, "servers": [ "192.168.1.1" ] }""");

            Assert.That(DNSConfiguration.TryParse(section, out var read, out var error),  Is.True,  error);

            var server = read!.Servers!.Single();

            Assert.Multiple(() => {
                Assert.That(read.Enabled,                  Is.True);
                Assert.That(server.IPAddress?.ToString(),  Is.EqualTo("192.168.1.1"));
                Assert.That(server.Port.ToUInt16(),        Is.EqualTo(53));
                Assert.That(server.Transport,              Is.EqualTo(DNSTransport.UDP));
            });

        }

        #endregion

        #region TheLongFormIsWhatThePageWritesBack()

        /// <summary>
        /// A server with more to say about it is read, and written back as it
        /// was - which is what makes it the form the DNS page saves the list in.
        /// </summary>
        [Test]
        public void TheLongFormIsWhatThePageWritesBack()
        {

            var entry = JObject.Parse("""{ "address": "192.168.1.1", "port": 53, "transport": "UDP", "queryTimeoutSeconds": 2 }""");

            Assert.That(DNSConfiguration.TryParseServer(entry, out var server, out var error),  Is.True,  error);

            var written = DNSConfiguration.ServerJSON(server!);

            Assert.Multiple(() => {
                Assert.That(written.Value<String>("address"),              Is.EqualTo("192.168.1.1"));
                Assert.That(written.Value<Int32> ("port"),                 Is.EqualTo(53));
                Assert.That(written.Value<String>("transport"),            Is.EqualTo("UDP"));
                Assert.That(written.Value<Double>("queryTimeoutSeconds"),  Is.EqualTo(2));
            });

        }

        #endregion

        #region TheFormTheLogNamesAServerInIsRefusedWithASentence(Entry)

        /// <summary>
        /// How the log names a name server, and an address with its port: not
        /// forms the section takes, so refused - with the entry named, and not
        /// with an exception out of the parser, which is what all three were.
        /// </summary>
        [TestCase("udp://213.133.98.98:53")]
        [TestCase("udp://[2a01:4f8:0:1::add:1010]:53")]
        [TestCase("213.133.98.98:53")]
        public void TheFormTheLogNamesAServerInIsRefusedWithASentence(String Entry)
        {

            var                section  = new JObject(new JProperty("servers", new JArray(Entry)));
            var                parsed   = true;
            DNSConfiguration?  read     = null;
            String?            error    = null;

            Assert.That(() => parsed = DNSConfiguration.TryParse(section, out read, out error),  Throws.Nothing);

            Assert.Multiple(() => {
                Assert.That(parsed,  Is.False);
                Assert.That(read,    Is.Null);
                Assert.That(error,   Does.Contain("'dns.servers'").And.Contain(Entry));
            });

        }

        #endregion

        #region ACSMSWhoseFileSaysSoStopsWithASentence()

        /// <summary>
        /// And at a start: the CSMS stops over the file the way it stops over
        /// any file it cannot read, saying what is wrong and where - rather than
        /// with an ArgumentException, which is how it stopped before.
        /// </summary>
        /// <remarks>
        /// Built and never started: the constructor is what reads the file.
        /// </remarks>
        [Test]
        public void ACSMSWhoseFileSaysSoStopsWithASentence()
        {

            var problem = Assert.Throws<InvalidOperationException>(
                              () => TestCSMSs.New(directory, JObject.Parse("""{ "dns": { "servers": [ "udp://213.133.98.98:53" ] } }"""))
                          );

            Assert.That(problem?.Message,  Does.Contain("'dns.servers'").
                                           And.Contain("udp://213.133.98.98:53").
                                           And.Contain(Path.Combine(directory, "configuration.json")));

        }

        #endregion

    }

}
