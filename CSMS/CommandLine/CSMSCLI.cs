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

using System.Reflection;

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;

using OCPPAdapter = cloud.charging.open.protocols.OCPPv2_1.NetworkingNode.OCPPAdapter;
using ICSMSCLI    = cloud.charging.open.protocols.OCPPv2_1.CSMS.CommandLine.ICSMSCLI;

#endregion

namespace cloud.charging.open.CSMS.CommandLine
{

    /// <summary>
    /// The command line of a running CSMS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The node's command line, with the commands every node has - syncNTS
    /// among them - and the console until 'quit', Ctrl+C or SIGTERM. What only
    /// a CSMS can be told is a command built from a CSMSCLI in this
    /// assembly, found as the node's are: a new command is a new file and
    /// nothing else.
    /// </para>
    /// <para>
    /// Here, beside the CSMS, and not in the program that runs it: what a
    /// CSMS can be told is the CSMS's, and is told over SSH as well as at the
    /// console. The CSMS hands it to whoever signs in over SSH by itself (see
    /// CSMS.cs), so that a CSMS run by another program - the test environment
    /// - has the same commands as one run by the program CSMSCLI. A program
    /// with commands of its own derives from this one and sets
    /// WWCPNode.CommandLines anew.
    /// </para>
    /// <para>
    /// And the OCPP library's operator commands - reset, remoteStart,
    /// getBaseReport, changeAvailability and the rest - sent to the charging
    /// station chosen with 'use'. They ask nobody whether they may: each is
    /// wrapped here in a <see cref="StationOperation"/>, which asks whether
    /// whoever is typing may run the stations before it lets one go. One whose
    /// name a command here already has is left out - the library's queryDNS,
    /// which stationQueryDNS is.
    /// </para>
    /// </remarks>
    public class CSMSCLI : NodeCLI,
                           ICSMSCLI
    {

        #region Properties

        /// <summary>
        /// The CSMS these commands are about.
        /// </summary>
        public CSMS CSMS { get; }

        /// <summary>
        /// What the OCPP library's commands send through: the OCPP node of
        /// this CSMS.
        /// </summary>
        OCPPAdapter ICSMSCLI.OCPP
            => CSMS.Node.OCPP;

        /// <summary>
        /// The charging stations connected now, as the OCPP library's commands
        /// ask for them.
        /// </summary>
        IEnumerable<NetworkingNode_Id> ICSMSCLI.ConnectedNetworkingNodeIds
        {
            get
            {
                foreach (var station in CSMS.ConnectedStations)
                    if (NetworkingNode_Id.TryParse(station, out var id))
                        yield return id;
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the command line of the given CSMS.
        /// </summary>
        /// <param name="CSMS">The running CSMS.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one is searched either way.</param>
        public CSMSCLI(CSMS               CSMS,
                       params Assembly[]  AssembliesWithCLICommands)

            : base(CSMS, AssembliesWithCLICommands)

        {

            this.CSMS = CSMS;

            RegisterCLIType(typeof(CSMSCLI));
            RegisterStationOperations();

        }

        /// <summary>
        /// Create the command line of the given CSMS on the given terminal,
        /// for the given caller - a session over SSH.
        /// </summary>
        /// <param name="CSMS">The running CSMS.</param>
        /// <param name="Terminal">What the command line is typed at and written on.</param>
        /// <param name="Caller">Who is typing at it.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one and the node's are searched either way.</param>
        public CSMSCLI(CSMS               CSMS,
                       ICLITerminal       Terminal,
                       CLICaller          Caller,
                       params Assembly[]  AssembliesWithCLICommands)

            : base(CSMS, Terminal, Caller, AssembliesWithCLICommands)

        {

            this.CSMS = CSMS;

            RegisterCLIType(typeof(CSMSCLI));
            RegisterStationOperations();

        }

        #endregion


        #region (private) RegisterStationOperations()

        /// <summary>
        /// The OCPP library's operator commands, each wrapped in what asks
        /// first whether whoever is typing may run the stations.
        /// </summary>
        /// <remarks>
        /// Not registered by their type, as the commands here are: that would
        /// let them go unasked. After everything else, so that a name already
        /// taken here is known to be.
        /// </remarks>
        private void RegisterStationOperations()
        {

            var taken = Commands.Select(command => NameOf(command.GetType())).
                                 OfType<String>().
                                 ToHashSet(StringComparer.OrdinalIgnoreCase);

            RegisterCommands([
                .. typeof(ICSMSCLI).Assembly.GetTypes().
                       Where (type => typeof(ICLICommand).IsAssignableFrom(type) &&
                                      !type.IsAbstract &&
                                      !type.IsInterface &&
                                      type.GetConstructor([ typeof(ICSMSCLI) ]) is not null &&
                                      NameOf(type) is String name &&
                                      !taken.Contains(name)).
                       Select(type => new StationOperation(this,
                                                           NameOf(type)!,
                                                           (ICLICommand) Activator.CreateInstance(type, this)!))
            ]);

        }

        #endregion

        #region (private static) NameOf(CommandType)

        /// <summary>
        /// What a command is typed as: its static CommandName, as every
        /// command of these libraries has one.
        /// </summary>
        private static String? NameOf(Type CommandType)

            => CommandType.GetField("CommandName", BindingFlags.Public | BindingFlags.Static)?.GetValue(null) as String;

        #endregion

        #region (protected override) GetPrompt()

        /// <summary>
        /// The CSMS's OCPP identity, because it is often tried out on one bench
        /// with a charging station and a vehicle, and three consoles should not
        /// have to be told apart by what scrolls past on them. It is the name
        /// the stations know it by, and the "ocpp" section of the file sets it.
        /// And the charging station chosen with 'use', where one is: what the
        /// OCPP commands send goes to it, and that should not have to be
        /// remembered.
        /// </summary>
        protected override String GetPrompt()

            => Environment.TryGetValue(EnvironmentKey.RemoteSystemId, out var station) && station.FirstOrDefault() is String inUse
                   ? $"{CSMS.Node.Id} [{inUse}]> "
                   : $"{CSMS.Node.Id}> ";

        #endregion

    }

}
