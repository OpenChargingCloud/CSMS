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

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// What a CSMS adds to the resources every node has, and the role of
    /// whoever runs the charging stations below it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The node brings the viewer, who may look at everything, and the
    /// administrators, who may do everything - the certificates included,
    /// which is one of the two resources nobody else may edit here: somebody
    /// who can add a certificate authority can let in a charging station that
    /// nobody issued a password to. The other is the roaming: who this
    /// operator is peered with is a contract with somebody else, and not a
    /// setting to be changed in passing.
    /// </para>
    /// <para>
    /// The configuration file may add roles to these and say differently what
    /// one of them may do - see the node's "roles" section. What is written
    /// here is what a CSMS is when its file says nothing.
    /// </para>
    /// </remarks>
    public static class CSMSAccess
    {

        #region Resources

        /// <summary>
        /// The server the charging stations connect to, and which of them may:
        /// its port, the security profiles it accepts, what it logs, the names
        /// it is reachable as - and the charging station logins and their
        /// groups.
        /// </summary>
        /// <remarks>
        /// The logins with the server rather than a resource of their own: a
        /// port nobody may come through is the same as no port, and one
        /// question to whoever runs the stations is what the page asks.
        /// </remarks>
        public const String  Stations   = "stations";

        /// <summary>
        /// The charging locations this operator publishes to its roaming
        /// partners.
        /// </summary>
        public const String  Locations  = "locations";

        /// <summary>
        /// Who this operator is in OCPI, the partners it is peered with, and
        /// what travels between them: registering a partner and taking one out.
        /// </summary>
        public const String  Roaming    = "roaming";

        /// <summary>
        /// All three.
        /// </summary>
        public static readonly IReadOnlyList<String>  Resources = [ Stations, Locations, Roaming ];

        #endregion

        #region Roles

        /// <summary>
        /// Whoever runs the charging stations: may point this CSMS at other
        /// name and time servers and ask whether they work, adds and takes out
        /// charging stations, and publishes the locations they stand at - but
        /// may not touch the certificates or the roaming partners.
        /// </summary>
        /// <remarks>
        /// Day-to-day operation. A name server that moved, a charging station
        /// that was replaced or a location that opened is theirs to put right.
        /// </remarks>
        public static readonly Role  CPO    = new ("cpo",
                                                   [ Permission.Read(Permission.AnyResource),
                                                     Permission.Edit(NodeResources.DNS),
                                                     Permission.Run (NodeResources.DNS),
                                                     Permission.Edit(NodeResources.NTS),
                                                     Permission.Run (NodeResources.NTS),
                                                     Permission.Edit(Stations),
                                                     Permission.Edit(Locations) ],
                                                   "runs the charging stations: their name and time servers, the stations and their locations");

        /// <summary>
        /// The one role a CSMS adds to the node's.
        /// </summary>
        public static readonly IReadOnlyList<Role>  Roles = [ CPO ];

        #endregion

    }

}
