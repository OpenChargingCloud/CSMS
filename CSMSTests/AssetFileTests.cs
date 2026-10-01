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

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What the OCPI library still holds for its files when the CSMS is
    /// disposed is written out first, and a line its file refuses is said in
    /// the CSMS's log.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library writes the assets - locations, tariffs, sessions, CDRs -
    /// through a queue, and nothing let go of it: what it still held when the
    /// CSMS stopped was never written, and the next start did not know it. A
    /// line its file refused was said to the debug log alone.
    /// </para>
    /// <para>
    /// Each test makes a CSMS of its own and disposes it itself, rather than
    /// the one of a fixture, whose TearDown would dispose it a second time.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class AssetFileTests
    {

        #region EveryAssetLineIsInItsFileOnceTheCSMSIsDisposed()

        /// <summary>
        /// Two thousand lines handed to the library at once, as the sessions
        /// and CDRs of a busy evening do, and the CSMS disposed right after
        /// them: every one is in the file, in order.
        /// </summary>
        [Test]
        public async Task EveryAssetLineIsInItsFileOnceTheCSMSIsDisposed()
        {

            var directory = TestCSMSs.TemporaryDirectory("assets");

            try
            {

                var csms  = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(directory, TestCSMSs.Offline));
                var file  = AssetsFile(csms);

                for (var number = 1; number <= 2000; number++)
                    await csms.OCPIAPI.WriteToDatabase(file, $"{{\"probe\":{number}}}");

                await csms.DisposeAsync();

                Assert.That(ProbesIn(file), Is.EqualTo(Enumerable.Range(1, 2000)),
                            "Not every line handed to the library before the CSMS was disposed is in its file.");

            }
            finally
            {
                TestCSMSs.Remove(directory);
            }

        }

        #endregion

        #region ALineItsFileRefusesIsInTheCSMSsLog()

        /// <summary>
        /// A line its file cannot take is an error in the CSMS's log, naming
        /// the file - and not the line, which can hold a session, a CDR or a
        /// token.
        /// </summary>
        /// <remarks>
        /// The file is made unwritable the way that stops root as well: a
        /// directory where it would be.
        /// </remarks>
        [Test]
        public async Task ALineItsFileRefusesIsInTheCSMSsLog()
        {

            var directory = TestCSMSs.TemporaryDirectory("assets-refused");

            try
            {

                var csms  = await TestPorts.StartedOnFreshPorts(() => TestCSMSs.New(directory, TestCSMSs.Offline));
                var file  = AssetsFile(csms);

                if (File.Exists(file))
                    File.Move(file, file + ".aside");

                Directory.CreateDirectory(file);

                await csms.OCPIAPI.WriteToDatabase(file, "{\"probe\":\"the line itself\"}");

                await csms.DisposeAsync();

                var said = csms.Log.Recent(100, Tag: "files").ToArray();

                Assert.That(said, Has.Length.EqualTo(1), "The line its file refused is not in the CSMS's log.");

                Assert.Multiple(() => {
                    Assert.That(said[0].Level,    Is.EqualTo(LogLevel.Error));
                    Assert.That(said[0].Tags,     Does.Contain("ocpi"));
                    Assert.That(said[0].Message,  Does.Contain($"'{file}' could not be written"));
                    Assert.That(said[0].Message,  Does.Not.Contain("the line itself"), "The line itself is in the log.");
                });

            }
            finally
            {
                TestCSMSs.Remove(directory);
            }

        }

        #endregion


        #region (private static) AssetsFile(Node)

        /// <summary>
        /// The file the library keeps the assets of OCPI 2.2.1 in - one of the
        /// versions a CSMS offers unless told otherwise.
        /// </summary>
        private static String AssetsFile(CSMS Node)

            => Path.Combine(
                   Node.OCPIDirectory,
                   protocols.OCPIv2_2_1.CommonAPI.DefaultAssetsDBFileName
               );

        #endregion

        #region (private static) ProbesIn(FileName)

        /// <summary>
        /// The numbers of the probe lines in a file, in the order they are in
        /// it: none where it is not there. Read the way a file the queue may
        /// still be writing to can be read.
        /// </summary>
        private static IEnumerable<Int32> ProbesIn(String FileName)
        {

            if (!File.Exists(FileName))
                return [];

            using var stream  = new FileStream(FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader  = new StreamReader(stream);

            var probes = new List<Int32>();

            while (reader.ReadLine() is String line)
                if (line.StartsWith("{\"probe\":"))
                    probes.Add(Int32.Parse(line["{\"probe\":".Length..^1]));

            return probes;

        }

        #endregion

    }

}
