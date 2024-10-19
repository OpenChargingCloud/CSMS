/*
 * Copyright (c) 2014-2024 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP OCPP <https://github.com/OpenChargingCloud/WWCP_OCPP>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.CLI;

#endregion

namespace org.GraphDefined.OCPP.CSMS.TestApp.CommandLine
{

    public class UseCommand(CLI CLI) : ACLICommand(CLI),
                                       ICLICommands
    {

        public static readonly String CommandName = nameof(UseCommand)[..^7].ToLowerFirstChar();

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length >= 1)
            {

                if (Arguments.Length == 1 &&
                    CommandName.StartsWith(Arguments[0], StringComparison.CurrentCultureIgnoreCase))
                {
                    return [ SuggestionResponse.Complete(CommandName) ];
                }

                if (Arguments.Length == 2)
                    return [ SuggestionResponse.Prefix($"{Arguments[0]} {Arguments[1]}") ];

            }

            return [];

        }

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (Arguments.Length == 2)
            {
                cli.Environment[CLI.DefaultStrings.RemoteSystemId] = Arguments[1];
                return Task.FromResult<String[]>([$"Using charging station '{Arguments[1]}'!"]);
            }

            return Task.FromResult<String[]>([$"Usage: {CommandName} <charging station>"]);

        }

        public override String Help()
        {
            return $"{CommandName} <charging station> - Uses the charging station with the specified name.";
        }

    }

}
