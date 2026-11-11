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

using System.Globalization;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.CSMS.CommandLine
{

    /// <summary>
    /// Which charging stations are connected now, and how: over a WebSocket
    /// from where, how much went each way and how long ago it last did - or
    /// over SSH.
    /// </summary>
    /// <remarks>
    /// The stations to choose from with 'use', and the first thing to look at
    /// when one does not answer: a connection nothing came over for minutes is
    /// one that went away without saying so. Anybody who may look at the
    /// stations may look at this.
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class ConnectionsCommand(CSMSCLI CLI) : ACLICommand<CSMSCLI>(CLI),
                                                   ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "connections";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
            {

                if (CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase))
                    return [ SuggestionResponse.CommandHelp(Help()) ];

                if (CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase))
                    return [ SuggestionResponse.CommandCompleted(CommandName) ];

            }

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (Arguments.Length != 1)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            if (!cli.MayDo(Permission.Read(CSMSAccess.Stations), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var connections = cli.CSMS.StationConnections;

            if (connections.Count == 0)
                return Task.FromResult<String[]>([ "No charging station is connected." ]);

            var now    = Timestamp.Now;   // the clock the WebSocket connections stamp their frames with
            var width  = connections.Max(connection => connection.Station.Length);

            return Task.FromResult<String[]>([
                $"{connections.Count} charging station connection(s):",
                .. connections.Select(connection => $"  {connection.Station.PadRight(width)}  " + (
                       connection.OverSSH
                           ? "over SSH"
                           : $"from {connection.From}, frames in/out {connection.FramesIn}/{connection.FramesOut}, " +
                             $"last in {Ago(now, connection.LastIn)}, last out {Ago(now, connection.LastOut)}"
                   ))
            ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - the charging stations connected now: from where, how many WebSocket frames went each way, " +
                "and how long ago the last did";

        #endregion


        #region (private static) Ago(Now, Then)

        private static String Ago(DateTimeOffset   Now,
                                  DateTimeOffset?  Then)

            => Then is DateTimeOffset then
                   ? $"{Math.Max(0, (Now - then).TotalSeconds).ToString("F1", CultureInfo.InvariantCulture)} s ago"
                   : "never";

        #endregion

    }

}
