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

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What every node has to answer, asked of a CSMS - the conformance suite
    /// of WWCP_Node_TestKit.
    /// </summary>
    /// <remarks>
    /// The sign-in, the configuration, name resolution and the time servers,
    /// the diagnostics, the log and its event stream, stopping with browsers
    /// watching, the certificate store and the web interface: what this suite
    /// had its own copies of, as every other kind of node had. What is left of
    /// those is what only a CSMS says - the OCPP identity in its status, its
    /// sections, its roles, and the kinds its store keeps.
    /// </remarks>
    public class CSMSConformance : NodeConformanceTests
    {

        protected override WWCPNode NewNode(String   Directory,
                                            JObject  Configuration)

            => TestCSMSs.New(Directory, Configuration);

    }

}
