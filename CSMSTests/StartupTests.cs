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
    /// a CSMS. The accounts are made by <c>Start()</c>, because creating
    /// one is asynchronous - so the tests about them start the CSMS, and
    /// pay for a socket to do it.
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


        #region AFirstStartMakesUpAnAccountAndKeepsOnlyItsHash()

        /// <summary>
        /// Nobody can sign in to a web interface with no accounts in it, and
        /// an unauthenticated setup page would be a door of its own. So the
        /// password is made up, handed back once, and kept only as a hash.
        /// </summary>
        [Test]
        public async Task AFirstStartMakesUpAnAccountAndKeepsOnlyItsHash()
        {

            await using var CSMS = TestCSMSs.New(directory, TestCSMSs.Offline);

            await CSMS.Start();

            Assert.Multiple(() => {

                Assert.That(CSMS.GeneratedPassword,      Is.Not.Null.And.Not.Empty);
                Assert.That(CSMS.ExtAPI.Users.Count(),   Is.EqualTo(1));
                Assert.That(CSMS.ExtAPI.Users.First().Id.ToString(),
                                                               Is.EqualTo(CSMS.DefaultAdminUser));

                // The password is nowhere below the accounts directory, in any
                // of the files the HTTPExt API writes - only the hash of it.
                var written = String.Join(
                                  "\n",
                                  Directory.GetFiles(CSMS.AccountsPath, "*", SearchOption.AllDirectories).
                                            Select(File.ReadAllText)
                              );

                Assert.That(written, Does.Not.Contain(CSMS.GeneratedPassword!),
                            "The password this CSMS made up was written to disk in the clear.");
                Assert.That(written, Does.Contain("$pbkdf2"));

            });

        }

        #endregion

        #region ASecondStartUsesTheAccountsItFindsAndMakesUpNothing()

        [Test]
        public async Task ASecondStartUsesTheAccountsItFindsAndMakesUpNothing()
        {

            String firstPassword;

            await using (var first = TestCSMSs.New(directory, TestCSMSs.Offline))
            {
                await first.Start();
                firstPassword = first.GeneratedPassword!;
            }

            await using var second = TestCSMSs.New(directory, TestCSMSs.Offline);

            await second.Start();

            Assert.Multiple(() => {
                Assert.That(second.GeneratedPassword,    Is.Null,
                            "A CSMS that found accounts made up another password anyway.");
                Assert.That(second.ExtAPI.Users.Count(), Is.EqualTo(1),
                            "A second account was made beside the one the first start wrote.");
            });

            // That the first password still opens it is checked over the wire
            // in AuthenticationTests.TheAccountSurvivesARestart; here what is
            // asked is only that nothing was made up a second time.
            Assert.That(firstPassword, Is.Not.Null.And.Not.Empty);

        }

        #endregion

        #region AnUnreadableConfigurationStopsTheCSMS()

        /// <summary>
        /// Somebody wrote down what their CSMS is and got it wrong.
        /// Quietly running as something else would be worse than stopping.
        /// </summary>
        [Test]
        public void AnUnreadableConfigurationStopsTheCSMS()
        {

            File.WriteAllText(Path.Combine(directory, "configuration.json"), "{ dns: [ unquoted");

            // Configuration: null, so that the broken file written above is
            // left exactly as it is.
            var problem = Assert.Throws<InvalidOperationException>(
                              () => TestCSMSs.New(directory)
                          );

            Assert.That(problem!.Message, Does.Contain("configuration.json"));

        }

        #endregion

        #region ACSMSWithNoFilesRunsOnItsDefaults()

        [Test]
        public async Task ACSMSWithNoFilesRunsOnItsDefaults()
        {

            await using var CSMS = TestCSMSs.New(directory);

            Assert.Multiple(() => {
                Assert.That(CSMS.DNSEnabled,           Is.True);
                Assert.That(CSMS.NTSEnabled,           Is.True);
                Assert.That(CSMS.Node.Id.ToString(),   Is.EqualTo(OCPPConfiguration.DefaultNodeId));
                Assert.That(CSMS.Node.VendorName,      Is.EqualTo(OCPPConfiguration.DefaultVendorName));
                Assert.That(CSMS.Version,              Is.Not.Empty);
                Assert.That(CSMS.CreatedAt,            Is.Not.EqualTo(default(DateTimeOffset)));
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

        #region TheClockIsSetBeforeAnythingAsksTheTime()

        /// <summary>
        /// The event log stamps its entries with the CSMS's clock, and it
        /// is built inside the constructor - so a CSMS handed a clock has
        /// to be using it from its very first line, or the log reads the system
        /// one and cannot be held against anything.
        /// </summary>
        [Test]
        public async Task TheClockIsSetBeforeAnythingAsksTheTime()
        {

            var clock = TestClock.At(2000, 1, 1);

            await using var CSMS = TestCSMSs.New(directory, TestCSMSs.Offline, clock);

            Assert.Multiple(() => {

                Assert.That(CSMS.CreatedAt,   Is.EqualTo(clock.Now));
                Assert.That(CSMS.TimeProvider, Is.SameAs(clock));

                // Everything the CSMS said while it was being built.
                Assert.That(CSMS.Log.Count, Is.GreaterThan(0),
                            "A CSMS that said nothing while starting up cannot show this.");

                Assert.That(CSMS.Log.Recent(100).Select(entry => entry.Timestamp),
                            Is.All.EqualTo(clock.Now),
                            "Something was logged against a clock other than the CSMS's own.");

            });

        }

        #endregion

        #region ASwitchedOffTimeClientScheduleNothing()

        /// <summary>
        /// The whole reason the fixtures write that section: switched off, no
        /// timer is put on the network at all.
        /// </summary>
        [Test]
        public async Task ASwitchedOffTimeClientSchedulesNothing()
        {

            await using var CSMS = TestCSMSs.New(directory, TestCSMSs.Offline);

            await CSMS.Start();

            Assert.Multiple(() => {

                Assert.That(CSMS.NTSEnabled, Is.False);

                Assert.That(CSMS.Log.Recent(200).Any(entry => entry.Message.Contains("not being checked")),
                            Is.True,
                            "A CSMS with its time client switched off did not say that it is not checking its clock.");

                Assert.That(CSMS.Log.Recent(200).Any(entry => entry.Message.Contains("will be checked against")),
                            Is.False,
                            "A CSMS with its time client switched off scheduled a check anyway.");

            });

            await CSMS.Stop();

        }

        #endregion

    }

}
