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

using org.GraphDefined.Vanaheimr.Hermod.Messaging;

using cloud.charging.open.protocols.WWCP.NetworkingNode;

using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// Who a request or a message that comes in may be from. In the overlay network a frame names its network
    /// path itself - [2, destination, path, id, action, payload] - and whom it names is whom this CSMS takes it
    /// for: the station whose SSH key a SignSSHKey enrols, whose CSR a SignCertificate has signed, whose
    /// transaction a TransactionEvent is. So a frame is taken only where the connection it came over may send
    /// it in that name:
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The last hop is the connection's node.</b> A node that sends a frame of its own names itself; one that
    /// forwards a frame puts itself at the end of its path. A path that ends in another node than the one this
    /// connection signed in as says what is not so.
    /// </para>
    /// <para>
    /// <b>A connection speaks for itself, and a local controller's for the stations behind it.</b> Whether a
    /// login is a local controller's is the operator's to say (<see cref="OCPP.ChargingStationLogin.LocalController"/>):
    /// any station can dial in the overlay network and name itself the way to another station, so a frame
    /// does not say it.
    /// </para>
    /// <para>
    /// A frame that is not taken is dropped, unanswered - an answer would go to the station it names, by the
    /// route to that station - and said in the log, with what to do where it was a local controller nobody had
    /// marked yet. In standard mode a frame names no path: the node puts in the connection's, which nothing
    /// here refuses.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region (private) AttachSenderGate(Node)

        private void AttachSenderGate(OCPPv2_1_CSMS.TestCSMSNode Node)
        {
            Node.OCPP.IN.SenderGate = (connection, node, path, action) => {

                if (WhyNotFrom(connection, node, path) is not String why)
                    return null;

                Log.Warning($"'{node}' sent {action} in the name of '{SourceOf(path)}', and it is dropped: {why}",
                            "ocpp", "station", "security");

                return why;

            };
        }

        #endregion

        #region WhyNotFrom(Connection, Node, Path)

        /// <summary>
        /// Why the given connection - signed in as the given node - may not send a frame of the given network
        /// path; null where it may.
        /// </summary>
        public String? WhyNotFrom(IMessageConnection  Connection,
                                  NetworkingNode_Id?  Node,
                                  NetworkPath         Path)
        {

            // What this CSMS dialled itself is not a station's.
            if (Connection.Role != ConnectionRole.Server)
                return null;

            if (Node is not NetworkingNode_Id node || node == NetworkingNode_Id.Zero)
                return "it came over a connection this CSMS knows no node of.";

            if (Path.Length == 0)
                return "its network path names nobody, and nobody it could be answered to.";

            if (Path.Last != node)
                return $"its network path ends in '{Path.Last}', but it came over the connection of '{node}'.";

            if (Path.Source == node)
                return null;

            if (!StationLogins.IsLocalController(node.ToString()))
                return $"'{node}' is no local controller, and sends in its own name alone. Where it is one, mark it as one: " +
                       $"'localControllers {node} on' on the command line, or on the page of the charging stations.";

            return null;

        }

        #endregion

        #region (private static) SourceOf(Path)

        private static String SourceOf(NetworkPath Path)
            => Path.Length > 0 ? Path.Source.ToString() : "nobody";

        #endregion

    }

}
