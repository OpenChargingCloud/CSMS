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

using NUnit.Framework;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The event stream every browser hangs on, as a proxy in front of the CSMS
    /// sees it.
    /// </summary>
    /// <remarks>
    /// Against a CSMS that is started, because what is tested is what goes over
    /// the wire: a header, and what the stream says while nothing happens.
    /// </remarks>
    public class EventStreamTests : ACSMSTests
    {

        #region (private static) ReadUntil(Reader, Wanted, Within)

        /// <summary>
        /// Read the stream line by line until a line satisfies the condition,
        /// and say whether one did in time.
        /// </summary>
        private static async Task<Boolean> ReadUntil(StreamReader           Reader,
                                                     Func<String, Boolean>  Wanted,
                                                     TimeSpan               Within)
        {

            using var timeout = new CancellationTokenSource(Within);

            try
            {
                while (await Reader.ReadLineAsync(timeout.Token) is String line)
                {
                    if (Wanted(line))
                        return true;
                }
            }
            catch (OperationCanceledException)
            { }

            return false;

        }

        #endregion


        #region TheStreamAsksAProxyNotToBufferIt()

        /// <summary>
        /// "X-Accel-Buffering: no" on the event stream.
        /// </summary>
        /// <remarks>
        /// nginx buffers what it passes on unless it is told otherwise, and a
        /// buffered event stream reached the browser as nothing at all - not even
        /// its header - until nginx gave up on it after 60 silent seconds. The
        /// Logs page said "reconnecting ..." all the while, and never asked for
        /// its snapshot, which it does when the stream opens. Measured behind
        /// nginx with the vehicle, whose stream this one is the sibling of.
        /// </remarks>
        [Test]
        public async Task TheStreamAsksAProxyNotToBufferIt()
        {

            using var http      = await SignedIn();
            using var response  = await http.GetAsync("/api/v1/events", HttpCompletionOption.ResponseHeadersRead);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                                                 Is.EqualTo(HttpStatusCode.OK));
                Assert.That(response.Content.Headers.ContentType?.MediaType,                     Is.EqualTo("text/event-stream"));
                Assert.That(response.Headers.TryGetValues("X-Accel-Buffering", out var values),  Is.True, "the header is there");
                Assert.That(values,                                                              Is.EqualTo(new[] { "no" }));
            });

        }

        #endregion

        #region ASilentStreamSaysSoAndThenCarriesOn()

        /// <summary>
        /// A comment whenever the stream has been silent for the heartbeat, and
        /// the next entry after it as if nothing had happened.
        /// </summary>
        /// <remarks>
        /// nginx gives up on an upstream that has sent nothing for 60 seconds, and
        /// a CSMS nobody is using says nothing for longer than that. The second
        /// half is the one that could go wrong: the stream waits for the next
        /// entry across the heartbeat instead of asking for it again, and an
        /// entry that arrived during one must neither be lost nor come twice.
        /// </remarks>
        [Test]
        public async Task ASilentStreamSaysSoAndThenCarriesOn()
        {

            CSMS.API.EventStreamHeartbeat = TimeSpan.FromMilliseconds(300);

            using var http      = await SignedIn();
            using var response  = await http.GetAsync("/api/v1/events", HttpCompletionOption.ResponseHeadersRead);
            using var reader    = new StreamReader(await response.Content.ReadAsStreamAsync());

            var heartbeat       = await ReadUntil(reader, line => line == ": keep-alive", TimeSpan.FromSeconds(10));

            var marker          = "A line for the event stream " + Guid.NewGuid().ToString("N")[..8];
            CSMS.Log.Info(marker, "test");

            var lines           = new List<String>();
            var entry           = await ReadUntil(reader, line => { lines.Add(line); return line.Contains(marker); }, TimeSpan.FromSeconds(10));

            // And the one after it, to be sure the stream is still waiting for
            // entries and not only for the heartbeat.
            var second          = marker + " (second)";
            CSMS.Log.Info(second, "test");

            var secondEntry     = await ReadUntil(reader, line => { lines.Add(line); return line.Contains(second); }, TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {
                Assert.That(heartbeat,                                             Is.True,   "a comment came while nothing was logged");
                Assert.That(entry,                                                 Is.True,   "the entry logged after the heartbeat arrived");
                Assert.That(secondEntry,                                           Is.True,   "and so did the one after it");
                Assert.That(lines.Count(line => line.Contains($"\"{marker}\"")),  Is.EqualTo(1), "once");
            });

        }

        #endregion

    }

}
