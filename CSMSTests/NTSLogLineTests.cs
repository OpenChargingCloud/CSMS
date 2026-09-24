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

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The lines a synchronisation writes into the log read the same whatever
    /// culture the machine writing them has.
    /// </summary>
    /// <remarks>
    /// They are English sentences and they end up in a log book, where numbers
    /// that change their punctuation with the machine are numbers somebody has
    /// to read twice. Under de-DE both used to carry a decimal comma.
    /// </remarks>
    [SetCulture("de-DE")]
    public class NTSLogLineTests
    {

        #region (private static) Answer(Name, OffsetMilliseconds)

        private static NTSMeasurementResult Answer(String  Name,
                                                   Double  OffsetMilliseconds)

            => new (DomainName.Parse(Name),
                    Guid.Empty) {

                   Success  = true,
                   NTP      = new NTPMeasurementResult {
                                  Success                 = true,
                                  NTSAuthenticationValid  = true,
                                  Offset                  = TimeSpan.FromMilliseconds(OffsetMilliseconds)
                              }

               };

        #endregion


        #region TheLineAGroupAnsweredWithHasItsNumbersWithAPoint()

        /// <summary>
        /// The half of the line that says what the group concluded is Norn's,
        /// and it wrote "+2,5 ms from 3 server(s), spread 2,0 ms" here.
        /// </summary>
        [Test]
        public void TheLineAGroupAnsweredWithHasItsNumbersWithAPoint()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a.example", 1.5), Answer("b.example", 2.5), Answer("c.example", 3.5) ],
                              MinServers:    2,
                              MaxDeviation:  TimeSpan.FromSeconds(60)
                          );

            Assert.That(CSMS.AnsweredLine("legal", 766, verdict),
                        Is.EqualTo("NTS: group 'legal' answered in 766 ms - +2.5 ms from 3 server(s), spread 2.0 ms."));

        }

        #endregion

        #region TheDeviationWarningHasItsNumbersWithAPointAndTheDeviationInFull()

        /// <summary>
        /// Both numbers with a point, and the agreed deviation with as many
        /// places as it has: it may be set as low as a millisecond, and a
        /// whole-second format wrote 0.001 s as "0 s" - the one number the
        /// warning exists to compare against.
        /// </summary>
        [Test]
        public void TheDeviationWarningHasItsNumbersWithAPointAndTheDeviationInFull()
        {

            Assert.That(CSMS.DeviationWarning("legal", TimeSpan.FromMilliseconds(2.2), TimeSpan.FromMilliseconds(1)),
                        Is.EqualTo("NTS: the time servers of group 'legal' disagree by 2.2 ms, which reaches the agreed deviation of 0.001 s."));

        }

        #endregion

    }

}
