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

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.Web;

using ICSMSCLI = cloud.charging.open.protocols.OCPPv2_1.CSMS.CommandLine.ICSMSCLI;

using cloud.charging.open.protocols.OCPPv2_1.CSMS.CommandLine;

#endregion

namespace cloud.charging.open.CSMS.CommandLine
{

    /// <summary>
    /// One of the OCPP library's operator commands - reset, remoteStart and
    /// the rest - with the question it does not ask itself in front of it:
    /// whether whoever is typing may run the charging stations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Asked when it runs, not when it is suggested: until a station is chosen
    /// with 'use' the library's commands are not even offered, and 'use' asks
    /// the same question. Asked again here because 'use' is not the only way
    /// to choose one - setEnv sets the same two values - and because a role
    /// can be taken away from an account that is signed in.
    /// </para>
    /// <para>
    /// What was sent, and to which station, is written into the log under who
    /// sent it - the command and not its arguments, which may carry a
    /// password of the station's network profile or a certificate.
    /// </para>
    /// <para>
    /// Not a command of this assembly found by its type: it is made by
    /// CSMSCLI for each of the library's, and has no constructor reflection
    /// would call.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line it runs in.</param>
    /// <param name="CommandName">What the command is typed as.</param>
    /// <param name="Command">The library's command.</param>
    public sealed class StationOperation(CSMSCLI      CLI,
                                         String       CommandName,
                                         ICLICommand  Command) : ICLICommand
    {

        #region Data

        /// <summary>
        /// What whoever runs one of these needs.
        /// </summary>
        public static readonly Permission Required = Permission.Run(CSMSAccess.Stations);

        #endregion

        #region Properties

        /// <summary>
        /// What the command is typed as.
        /// </summary>
        public String       CommandName  { get; } = CommandName;

        /// <summary>
        /// The library's command.
        /// </summary>
        public ICLICommand  Command      { get; } = Command;

        #endregion


        #region Suggest(Arguments)

        public IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => Command.Suggest(Arguments);

        #endregion

        #region Execute(Arguments, CancellationToken)

        public async Task<String[]> Execute(String[]           Arguments,
                                            CancellationToken  CancellationToken)
        {

            if (!CLI.MayDo(Required, CommandName, out var refused))
                return [ refused ];

            var station = ((ICSMSCLI) CLI).GetRemoteSystemId()?.ToString();

            if (station is not null)
                CLI.Node.Log.Notice(
                    $"{CLI.Caller.Asker} sent '{CommandName}' to the charging station '{station}' over OCPP.",
                    CLI.Caller.Tags("ocpp", "station")
                );

            return await Command.Execute(Arguments, CancellationToken);

        }

        #endregion

        #region Help()

        public String Help()

            => Command.Help();

        #endregion

        #region MayBeKept(Arguments)

        public Boolean MayBeKept(String[] Arguments)

            => Command.MayBeKept(Arguments);

        #endregion

    }

}
