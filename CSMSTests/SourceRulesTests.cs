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

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What the kit holds every kind's C# source to, asked of this CSMS's.
    /// </summary>
    public class SourceRulesTests
    {

        #region NoTextOfThisCSMSPutsAnArticleBeforeAName()

        /// <summary>
        /// Nothing this CSMS says puts an article in front of a name it
        /// interpolates. It said "A {algorithm.Name} key could not be
        /// generated", which is wrong for every key it makes - "A ECDSA P-256",
        /// "A RSA 2048" - and put "a" before the name of a key twice more,
        /// where the platform cannot present a certificate for it.
        /// </summary>
        [Test]
        public void NoTextOfThisCSMSPutsAnArticleBeforeAName()
        {

            var repository = SourceRules.RepositoryAbove(AppContext.BaseDirectory, "CSMS", "CSMSTests");

            Assert.That(SourceRules.ArticlesBeforeANameIn(Path.Combine(repository, "CSMS")), Is.Empty);

        }

        #endregion

    }

}
