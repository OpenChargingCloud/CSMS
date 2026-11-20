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

using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.OCPP;
using cloud.charging.open.protocols.OCPP.Node.Serving;
using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What the CSMS keeps of its own beside what the node below keeps - the
    /// OCPP server's keys, the charging stations' logins and the OCPI
    /// partners' tokens - is for the account it runs under alone, and what an
    /// earlier version left open is closed at the next start.
    /// </summary>
    /// <remarks>
    /// Every test starts below a directory everybody may read, as a CSMS kept
    /// in a folder at the root of a Windows drive is: a temporary directory is
    /// its user's alone already, and would pass these tests without anything
    /// done here.
    /// </remarks>
    public class OwnerOnlyTests
    {

        #region Data

        private String     directory  = default!;
        private TestClock  clock      = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeAnOpenDirectory()
        {
            directory = TestCSMSs.TemporaryDirectory("owner-only");
            clock     = TestClock.At(2026, 6, 1);
            OwnerOnlyChecks.OpenToEverybody(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
        {
            TestCSMSs.Remove(directory);
        }

        #endregion


        #region TheStationLoginsAreTheOwnersAlone()

        /// <summary>
        /// The file of the charging stations' logins, which holds their
        /// passwords, beside a configuration file in an open directory.
        /// </summary>
        [Test]
        public void TheStationLoginsAreTheOwnersAlone()
        {

            var file   = Path.Combine(directory, WebSocketLogins.DefaultFileName);
            var logins = new WebSocketLogins(file, clock);

            Assert.That(logins.TryLoad(out var loadError), Is.True, loadError);
            Assert.That(logins.TrySetPasswordAuthentication("cs001", "a-password-long-enough-for-ocpp", null, null, out var error), Is.True, error);

            Assert.That(File.Exists(file), Is.True, "The logins were not written.");
            Assert.That(OwnerOnlyChecks.OthersMayGetIn(file), Is.Empty, "Others may read the charging stations' logins.");

        }

        #endregion

        #region StationLoginsLeftOpenAreClosedAtTheNextStart()

        /// <summary>
        /// A file of logins an earlier version wrote as the directory had it
        /// is closed when it is read again.
        /// </summary>
        [Test]
        public void StationLoginsLeftOpenAreClosedAtTheNextStart()
        {

            var file = Path.Combine(directory, WebSocketLogins.DefaultFileName);

            File.WriteAllText(file, """{ "logins": [] }""");

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(file, (UnixFileMode) 0b110_100_100);

            Assert.That(OwnerOnlyChecks.OthersMayGetIn(file), Is.Not.Empty, "The test's file of logins is not open to begin with.");

            Assert.That(new WebSocketLogins(file, clock).TryLoad(out var error), Is.True, error);

            Assert.That(OwnerOnlyChecks.OthersMayGetIn(file), Is.Empty, "Others may still read the charging stations' logins.");

        }

        #endregion

        #region TheOCPIDirectoryIsTheOwnersAlone()

        /// <summary>
        /// The directory of the OCPI partners and their tokens, both when the
        /// CSMS makes it and when an earlier version left it open.
        /// </summary>
        [TestCase(false)]
        [TestCase(true)]
        public async Task TheOCPIDirectoryIsTheOwnersAlone(Boolean LeftOpenBefore)
        {

            if (LeftOpenBefore)
                OwnerOnlyChecks.OpenToEverybody(Path.Combine(directory, CSMS.OCPIDirectoryName));

            await using var csms = TestCSMSs.New(directory, TestCSMSs.Offline, clock);

            Assert.That(Directory.Exists(csms.OCPIDirectory), Is.True, "The OCPI directory was not made.");
            Assert.That(OwnerOnlyChecks.OthersMayGetIn(csms.OCPIDirectory), Is.Empty, "Others may get into the OCPI directory.");

        }

        #endregion

    }

}
