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

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The CSMS's log on disk: the file it writes, from its very first line.
    /// </summary>
    /// <remarks>
    /// What goes into a log file, which file it goes into, and what happens on
    /// the day the file cannot be written is the node's, and asked in
    /// WWCP_Node_Tests. What is here is that a CSMS attaches its file early
    /// enough, and calls it what a CSMS's files are called.
    /// </remarks>
    [TestFixture]
    public class FileLogTests
    {

        #region ACSMSWritesItsVeryFirstEntryIntoTheFile()

        /// <summary>
        /// The file is attached before the CSMS says anything at all.
        /// </summary>
        /// <remarks>
        /// The first entry a CSMS writes is that it is starting up, and a
        /// file attached after that would begin in the middle of the story -
        /// with the one line that dates the run already missing from it.
        /// </remarks>
        [Test]
        public async Task ACSMSWritesItsVeryFirstEntryIntoTheFile()
        {

            var directory  = TestCSMSs.TemporaryDirectory("file-log");
            var logs       = Path.Combine(directory, "logs");

            try
            {

                var csms = new CSMS(
                               HTTPPort:        IPPort.Parse(TestPorts.Free()),
                               AccountsPath:    Path.Combine(directory, "accounts"),
                               ConfigFile:      new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                               LogToConsole:    false,
                               LogPath:         logs,
                               BridgeDebugLog:  false
                           );

                String[] lines;

                try
                {

                    var file = Directory.GetFiles(logs, "csms-*.log").Single();

                    using var reader = new StreamReader(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));

                    lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);

                }
                finally
                {
                    await csms.DisposeAsync();
                }

                Assert.That(lines.FirstOrDefault(), Does.Contain("[csms] CSMS v").And.Contain("starting up."));

            }
            finally
            {
                TestCSMSs.Remove(directory);
            }

        }

        #endregion

    }

}
