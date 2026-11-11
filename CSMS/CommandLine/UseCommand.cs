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
using org.GraphDefined.Vanaheimr.Illias;

using OCPPStrings = cloud.charging.open.protocols.OCPPv2_1.CSMS.CommandLine.DefaultStrings;

#endregion

namespace cloud.charging.open.CSMS.CommandLine
{

    /// <summary>
    /// Choose the charging station the OCPP commands are sent to: reset,
    /// remoteStart, getBaseReport and the rest of the OCPP library's.
    /// </summary>
    /// <remarks>
    /// <para>
    /// use - which one is chosen. use &lt;station&gt; - choose a connected
    /// one. use - - choose none again. Until one is chosen the OCPP commands
    /// are not offered at all: they would not know where to go.
    /// </para>
    /// <para>
    /// Choosing one is the first step of running it, and needs what running
    /// it needs (see <see cref="StationOperation"/>): a viewer is told so here
    /// and not after typing the whole command. Each session chooses its own,
    /// and the prompt says which.
    /// </para>
    /// <para>
    /// Always OCPP 2.1, as the library's commands ask for it: this CSMS is an
    /// OCPP 2.1 node, and a station that came in over 2.0.1 is spoken to by it
    /// all the same.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class UseCommand(CSMSCLI CLI) : ACLICommand<CSMSCLI>(CLI),
                                           ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "use";

        /// <summary>
        /// What chooses none again.
        /// </summary>
        public const String None = "-";

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

                return [];

            }

            if (Arguments.Length == 2 &&
                CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase))
            {

                var typed = Arguments[1];

                return cli.CSMS.ConnectedStations.
                           Where (station => station.StartsWith(typed, StringComparison.OrdinalIgnoreCase)).
                           Select(station => station.Equals(typed, StringComparison.OrdinalIgnoreCase)
                                                 ? SuggestionResponse.ParameterCompleted($"{CommandName} {station}")
                                                 : SuggestionResponse.ParameterPrefix   ($"{CommandName} {station}")).
                           ToArray();

            }

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (Arguments.Length == 1)
                return Task.FromResult<String[]>(
                           InUse() is String inUse
                               ? [ $"Using the charging station '{inUse}': the OCPP commands go to it." ]
                               : [ $"No charging station is in use: '{CommandName} <station>' chooses one of those connected." ]
                       );

            if (Arguments.Length != 2)
                return Task.FromResult<String[]>([ $"Usage: {Help()}" ]);

            var station = Arguments[1].Trim();

            if (station == None)
            {

                cli.Environment.TryRemove(EnvironmentKey.RemoteSystemId,          out _);
                cli.Environment.TryRemove(EnvironmentKey.RemoteSystemOCPPVersion, out _);

                return Task.FromResult<String[]>([ "No charging station is in use any more." ]);

            }

            if (!cli.MayDo(StationOperation.Required, CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            // As this CSMS let it in: the name it is known by in the log, and
            // the one the OCPP node sends to.
            var connected = cli.CSMS.ConnectedStations.FirstOrDefault(id => id.Equals(station, StringComparison.OrdinalIgnoreCase));

            if (connected is null)
                return Task.FromResult<String[]>([ $"The charging station '{station}' is not connected." ]);

            Set(EnvironmentKey.RemoteSystemId,           connected);
            Set(EnvironmentKey.RemoteSystemOCPPVersion,  OCPPStrings.OCPPv2_1);

            return Task.FromResult<String[]>([ $"Using the charging station '{connected}': the OCPP commands go to it." ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [<station> | {None}] - choose the connected charging station the OCPP commands go to " +
                "(reset, remoteStart, getBaseReport, ...), or none; without one, say which is chosen";

        #endregion


        #region (private) InUse()

        private String? InUse()

            => cli.Environment.TryGetValue(EnvironmentKey.RemoteSystemId, out var values)
                   ? values.FirstOrDefault()
                   : null;

        #endregion

        #region (private) Set(Key, Value)

        private void Set(EnvironmentKey  Key,
                         String          Value)
        {
            if (!cli.Environment.TryAdd(Key, new ConcurrentList<String>(Value)))
                cli.Environment[Key].TrySet(Value);
        }

        #endregion

    }

}
