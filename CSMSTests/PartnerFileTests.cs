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

using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// A roaming partner added or removed while the file the OCPI library
    /// keeps the partners of a version in cannot be written: 500 and why, and
    /// nothing changed, neither now nor at the next start.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both were answered as done. The library wrote the line into a queue
    /// that told the debug log alone that it could not: an added partner was
    /// listed, its token opening this operator, and gone at the next start; a
    /// removed one was back at the next start, its token opening this operator
    /// again (found by the roaming hub, and changed in WWCP_OCPI bb8c6601).
    /// </para>
    /// <para>
    /// The file is made unwritable the way that stops root as well: a
    /// directory where it would be. All three versions are offered, because
    /// each keeps its partners in a file of its own and is bound to this CSMS
    /// by an adapter of its own.
    /// </para>
    /// </remarks>
    public class PartnerFileTests : ACSMSTests
    {

        #region Configuration - a CSMS that offers every version

        /// <summary>
        /// The default is 2.1.1 and 2.2.1.
        /// </summary>
        protected override JObject Configuration

            => new (
                   new JProperty("nts",   new JObject(
                       new JProperty("enabled",  false)
                   )),
                   new JProperty("ocpi",  new JObject(
                       new JProperty("versions",  new JArray("2.1.1", "2.2.1", "2.3.0"))
                   ))
               );

        #endregion


        #region APartnerIsNotAddedWhereItsFileCannotTakeIt(Version)

        /// <summary>
        /// A partner the file of its version cannot take is not added: 500 and
        /// why, not in the list, and not there at the next start.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task APartnerIsNotAddedWhereItsFileCannotTakeIt(String Version)
        {

            using var admin = await SignedIn();

            var file      = BlockPartnersFile(Version);

            var response  = await admin.PostAsync("/api/v1/ocpi/partners", Partner(Version));
            var text      = await response.Content.ReadAsStringAsync();
            var listed    = await ListedPartners(admin);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);
                Assert.That(text,   Does.Contain(Path.GetFileName(file)),  "The answer does not say which file refused.");
                Assert.That(text,   Does.Contain("was not added"),         "The answer does not say that nothing was added.");
                Assert.That(listed, Is.Empty,                              "The partner the file refused is listed all the same.");
            });

            Assert.That(await PartnersAfterARestart(file), Is.Empty);

        }

        #endregion

        #region APartnerIsNotRemovedWhereItsFileCannotTakeIt(Version)

        /// <summary>
        /// A partner whose removal the file of its version cannot take is not
        /// removed: 500 and why, still in the list, its token still opening
        /// this operator, and still there at the next start.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task APartnerIsNotRemovedWhereItsFileCannotTakeIt(String Version)
        {

            using var admin = await SignedIn();

            var id = await AddPartner(admin, Version);

            // What the next start below reads the partner back from.
            Assert.That(await File.ReadAllTextAsync(PartnersFile(Version)), Does.Contain(protocols.OCPI.CommonHTTPAPI.addRemoteParty),
                        "The partner that was added is not in its file.");

            var file      = BlockPartnersFile(Version);

            var response  = await admin.DeleteAsync($"/api/v1/ocpi/partners/{Version}/{id}");
            var text      = await response.Content.ReadAsStringAsync();
            var listed    = await ListedPartners(admin);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.InternalServerError), text);
                Assert.That(text,   Does.Contain(Path.GetFileName(file)),  "The answer does not say which file refused.");
                Assert.That(text,   Does.Contain("its token still opens"), "The answer does not say what is still so.");
                Assert.That(listed, Does.Contain(id),                      "The partner the file would not let go of is gone from the list.");
            });

            Assert.That(await PartnersAfterARestart(file), Does.Contain(id));

        }

        #endregion

        #region APartnerIsRemovedForGood(Version)

        /// <summary>
        /// A partner removed while its file can be written is gone: 200, not in
        /// the list, and not there at the next start.
        /// </summary>
        [TestCase("2.1.1")]
        [TestCase("2.2.1")]
        [TestCase("2.3.0")]
        public async Task APartnerIsRemovedForGood(String Version)
        {

            using var admin = await SignedIn();

            var id = await AddPartner(admin, Version);

            var response  = await admin.DeleteAsync($"/api/v1/ocpi/partners/{Version}/{id}");
            var text      = await response.Content.ReadAsStringAsync();
            var listed    = await ListedPartners(admin);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), text);
                Assert.That(listed, Does.Not.Contain(id), "The partner that was removed is still listed.");
            });

            Assert.That(await PartnersAfterARestart(), Does.Not.Contain(id));

        }

        #endregion


        #region (private static) Partner(Version)

        /// <summary>
        /// The request body of the partner every test here adds, on the given
        /// version: an EMSP that comes to this operator with the token it is
        /// given.
        /// </summary>
        private static StringContent Partner(String Version)

            => JSONBody(
                   new JProperty("version",      Version),
                   new JProperty("countryCode",  "DE"),
                   new JProperty("partyId",      "GDF"),
                   new JProperty("role",         "EMSP"),
                   new JProperty("name",         "Test EMSP")
               );

        #endregion

        #region (private static) AddPartner(Admin, Version)

        /// <summary>
        /// Add the partner through the JSON API, on the given version, and hand
        /// back its identification.
        /// </summary>
        private static async Task<String> AddPartner(HttpClient  Admin,
                                                     String      Version)
        {

            var response  = await Admin.PostAsync("/api/v1/ocpi/partners", Partner(Version));
            var text      = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created),
                        $"Adding the partner answered {(Int32) response.StatusCode}: {text}");

            return JObject.Parse(text).Value<String>("id")!;

        }

        #endregion

        #region (private static) ListedPartners(HTTP)

        /// <summary>
        /// The partners the JSON API lists, by their identification.
        /// </summary>
        private static async Task<String[]> ListedPartners(HttpClient HTTP)

            => [.. ((await GetJSON(HTTP, "/api/v1/ocpi/partners"))["partners"] as JArray ?? new JArray()).
                   Select(partner => partner.Value<String>("id") ?? "")];

        #endregion

        #region (private) PartnersFile(Version) / BlockPartnersFile(Version)

        /// <summary>
        /// The file the library keeps the partners of a version in.
        /// </summary>
        private String PartnersFile(String Version)

            => Path.Combine(
                   CSMS.OCPIDirectory,
                   Version switch {
                       "2.1.1"  => protocols.OCPIv2_1_1.CommonAPI.DefaultRemotePartyDBFileName,
                       "2.2.1"  => protocols.OCPIv2_2_1.CommonAPI.DefaultRemotePartyDBFileName,
                       "2.3.0"  => protocols.OCPIv2_3_0.CommonAPI.DefaultRemotePartyDBFileName,
                       _        => throw new ArgumentException($"This CSMS offers no OCPI {Version}.", nameof(Version))
                   }
               );

        /// <summary>
        /// Make the file the library keeps the partners of a version in
        /// unwritable: a directory where it is, which stops root as well. What
        /// it held is put aside, for the next start to find again.
        /// </summary>
        private String BlockPartnersFile(String Version)
        {

            var file = PartnersFile(Version);

            if (File.Exists(file))
                File.Move(file, file + ".aside");

            System.IO.Directory.CreateDirectory(file);

            return file;

        }

        #endregion

        #region (private) PartnersAfterARestart(BlockedPartnersFile = null)

        /// <summary>
        /// Stop this CSMS, give a partners' file that was blocked back what it
        /// held, and ask the next start in the same directory which partners it
        /// knows.
        /// </summary>
        private async Task<String[]> PartnersAfterARestart(String? BlockedPartnersFile = null)
        {

            await CSMS.Stop();

            if (BlockedPartnersFile is not null)
            {

                System.IO.Directory.Delete(BlockedPartnersFile);

                if (File.Exists(BlockedPartnersFile + ".aside"))
                    File.Move(BlockedPartnersFile + ".aside", BlockedPartnersFile);

            }

            // Made again, on fresh ports, where another test run on this
            // machine took one before the CSMS could bind it - in the same
            // directory all the same, so every attempt reads the same files.
            var again = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(Directory, Configuration, Clock));

            try
            {
                return [.. again.OCPIVersions.SelectMany(version => version.RemoteParties).Select(partner => partner.Id.ToString())];
            }
            finally
            {
                await again.DisposeAsync();
            }

        }

        #endregion

    }

}
