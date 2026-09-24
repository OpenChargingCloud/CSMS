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

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// Host names read as host names wherever somebody reads them.
    /// </summary>
    /// <remarks>
    /// A domain name prints itself absolutely, with the root label on the end.
    /// That is right for a name on its way back into the configuration file and
    /// wrong in the middle of a sentence, where four of them in a row look like
    /// four typing mistakes: "ptbtime1.ptb.de., ptbtime2.ptb.de.".
    /// </remarks>
    [TestFixture]
    public class NTSNamesTests
    {

        #region Data

        private String directory = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
            => directory = TestCSMSs.TemporaryDirectory("nts-names");

        [TearDown]
        public void RemoveTheDirectory()
            => TestCSMSs.Remove(directory);

        #endregion

        #region (private) TimerlessClock

        /// <summary>
        /// The system's time, and timers that never fire.
        /// </summary>
        /// <remarks>
        /// For a CSMS started with NTS switched on, which schedules a check of
        /// its clock a minute in. A test has no business asking the PTB the
        /// time, and nothing here waits for a timer.
        /// </remarks>
        private sealed class TimerlessClock : TimeProvider
        {

            public override ITimer CreateTimer(TimerCallback  Callback,
                                               Object?        State,
                                               TimeSpan       DueTime,
                                               TimeSpan       Period)

                => new NeverFires();

            private sealed class NeverFires : ITimer
            {
                public Boolean   Change(TimeSpan DueTime, TimeSpan Period) => true;
                public void      Dispose() { }
                public ValueTask DisposeAsync() => ValueTask.CompletedTask;
            }

        }

        #endregion


        #region TheLineAtTheStartNamesTheServersAsTheyAreRead()

        /// <summary>
        /// The line written once at a start, which is what somebody reads to
        /// find out whether their file took effect.
        /// </summary>
        [Test]
        public async Task TheLineAtTheStartNamesTheServersAsTheyAreRead()
        {

            await using var csms = TestCSMSs.New(directory,
                                                 new JObject(new JProperty("nts", new JObject(new JProperty("enabled", true)))),
                                                 new TimerlessClock());

            await csms.Start();

            var line = csms.Log.Recent(100).Select(entry => entry.Message).
                                            FirstOrDefault(message => message.StartsWith("The clock of this CSMS will be checked against", StringComparison.Ordinal));

            Assert.That(line,  Is.EqualTo("The clock of this CSMS will be checked against " +
                                          "ptbtime1.ptb.de, ptbtime2.ptb.de, ptbtime3.ptb.de, ptbtime4.ptb.de " +
                                          "every 15 minute(s), at least 2 of which must answer."));

        }

        #endregion

        #region AChangeOfServersIsWrittenDownAsTheyAreRead()

        /// <summary>
        /// And the line that says the servers changed. What goes into the file
        /// keeps the root dot - that is the form a name is parsed back from.
        /// </summary>
        [Test]
        public async Task AChangeOfServersIsWrittenDownAsTheyAreRead()
        {

            await using var csms = TestCSMSs.New(directory, TestCSMSs.Offline);

            Assert.That(csms.TryUpdateNTSConfiguration(new JObject(new JProperty("servers", new JArray("a.example", "b.example"))), out var error),
                        Is.True,
                        error);

            // The last such line: the file this CSMS was built from switched
            // NTS off, which was the first.
            var line   = csms.Log.Recent(100).Select(entry => entry.Message).
                                              LastOrDefault(message => message.StartsWith("NTS configuration changed", StringComparison.Ordinal));

            var onDisk = JObject.Parse(File.ReadAllText(csms.ConfigFile.Path));

            Assert.Multiple(() => {
                Assert.That(line,                                         Does.Contain("time servers = a.example, b.example"));
                Assert.That(line,                                         Does.Not.Contain("a.example."));
                Assert.That(onDisk["nts"]?["servers"]?[0]?.Value<String>(),  Is.EqualTo("a.example."));
            });

        }

        #endregion

    }

}
