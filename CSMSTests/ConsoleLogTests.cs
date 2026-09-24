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
    /// Who gets to write on the console once somebody is typing on it.
    /// </summary>
    /// <remarks>
    /// The command line of the program owns the line being typed, and the
    /// CSMS's log has to ask it for the screen rather than write over that
    /// line. What is measured here is the CSMS's half of that: every entry
    /// the console would have shown is handed over, whole, and nothing that
    /// the console would not have shown is.
    /// </remarks>
    [TestFixture]
    public class ConsoleLogTests
    {

        #region Data

        private String  directory  = "";
        private CSMS?   csms;

        #endregion

        #region TearDown

        [TearDown]
        public async Task TakeItAwayAgain()
        {

            if (csms is not null)
                await csms.DisposeAsync();

            csms = null;

            TestCSMSs.Remove(directory);

        }

        #endregion


        #region EveryEntryTheConsoleWouldShowIsHandedOver()

        /// <summary>
        /// Handed over rather than written, and only what the console shows.
        /// </summary>
        /// <remarks>
        /// What is handed over is run here, with the console's output caught,
        /// because being asked is only half of it: what the command line is
        /// given has to write the entry, and write all of it.
        /// </remarks>
        [Test]
        public void EveryEntryTheConsoleWouldShowIsHandedOver()
        {

            directory  = TestCSMSs.TemporaryDirectory("console-log");
            csms       = TestCSMSs.New(directory, TestCSMSs.Offline, LogToConsole: true);

            var handed = new List<Action>();

            csms.ShareConsoleWith(handed.Add);

            csms.Log.Info ("Somebody is typing, and this has to wait its turn.", "test");
            csms.Log.Debug("Below what the console shows, so nobody is asked.",  "test");

            var output   = new StringWriter();
            var previous = Console.Out;

            Console.SetOut(output);

            try
            {
                foreach (var write in handed)
                    write();
            }
            finally
            {
                Console.SetOut(previous);
            }

            Assert.Multiple(() => {

                Assert.That(handed, Has.Count.EqualTo(1),
                            "Either an entry went past whoever holds the console, or a debug entry was put on it.");

                // The message rather than the whole line, whose shape depends
                // on whether this runner's output counts as a terminal: in
                // colour the level and the tags are written without brackets.
                Assert.That(output.ToString(), Does.Contain("Somebody is typing, and this has to wait its turn."));

            });

        }

        #endregion

        #region WithoutAConsoleThereIsNothingToShare()

        /// <summary>
        /// A CSMS whose log does not reach the console has nothing to hand
        /// over, and asking it to is not an error.
        /// </summary>
        [Test]
        public void WithoutAConsoleThereIsNothingToShare()
        {

            directory  = TestCSMSs.TemporaryDirectory("console-log");
            csms       = TestCSMSs.New(directory, TestCSMSs.Offline);

            var handed = 0;

            csms.ShareConsoleWith(write => handed++);

            csms.Log.Warning("Nobody is watching the console of this one.", "test");

            Assert.That(handed, Is.Zero);

        }

        #endregion

    }

}
