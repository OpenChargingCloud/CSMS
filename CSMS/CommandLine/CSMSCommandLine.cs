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

using cloud.charging.open.protocols.WWCP.Node.CommandLine;

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
    /// a CSMS can be told is a command built from a CSMSCommandLine in this
    /// assembly, found as the node's are: a new command is a new file and
    /// nothing else.
    /// </para>
    /// <para>
    /// Here, beside the CSMS, and not in the program that runs it: what a
    /// CSMS can be told is the CSMS's, and is told over SSH as well as at the
    /// console. The CSMS hands it to whoever signs in over SSH by itself (see
    /// CSMS.cs), so that a CSMS run by another program - the test environment
    /// - has the same commands as one run by CSMSCLI. A program with commands
    /// of its own derives from this one and sets WWCPNode.CommandLines anew.
    /// </para>
    /// </remarks>
    public class CSMSCommandLine : NodeCLI
    {

        #region Properties

        /// <summary>
        /// The CSMS these commands are about.
        /// </summary>
        public CSMS CSMS { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the command line of the given CSMS.
        /// </summary>
        /// <param name="CSMS">The running CSMS.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one is searched either way.</param>
        public CSMSCommandLine(CSMS               CSMS,
                               params Assembly[]  AssembliesWithCLICommands)

            : base(CSMS, AssembliesWithCLICommands)

        {

            this.CSMS = CSMS;

            RegisterCLIType(typeof(CSMSCommandLine));

        }

        /// <summary>
        /// Create the command line of the given CSMS on the given terminal,
        /// for the given caller - a session over SSH.
        /// </summary>
        /// <param name="CSMS">The running CSMS.</param>
        /// <param name="Terminal">What the command line is typed at and written on.</param>
        /// <param name="Caller">Who is typing at it.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one and the node's are searched either way.</param>
        public CSMSCommandLine(CSMS               CSMS,
                               ICLITerminal       Terminal,
                               CLICaller          Caller,
                               params Assembly[]  AssembliesWithCLICommands)

            : base(CSMS, Terminal, Caller, AssembliesWithCLICommands)

        {

            this.CSMS = CSMS;

            RegisterCLIType(typeof(CSMSCommandLine));

        }

        #endregion


        #region (protected override) GetPrompt()

        /// <summary>
        /// The CSMS's OCPP identity, because it is often tried out on one bench
        /// with a charging station and a vehicle, and three consoles should not
        /// have to be told apart by what scrolls past on them. It is the name
        /// the stations know it by, and the "ocpp" section of the file sets it.
        /// </summary>
        protected override String GetPrompt()

            => $"{CSMS.Node.Id}> ";

        #endregion

    }

}
