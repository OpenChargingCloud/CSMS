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
using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.CSMS.CommandLine
{

    /// <summary>
    /// The logins of gateways: the ones that, like a local controller's, may send in the overlay network in the
    /// name of the charging stations behind them. Any other login speaks for itself alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// gateways lists them; gateways &lt;login&gt; on marks a login as a gateway's, and off no longer. To this
    /// CSMS a gateway is what a local controller is; it is marked as what it is so that the list, the log and a
    /// connection that dials it say so. A login is the one or the other: marked as a gateway's, it is no local
    /// controller's any more.
    /// </para>
    /// <para>
    /// Looking is at the stations' permission, marking at the stations' editing, as for local controllers. The
    /// console may do everything.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class GatewaysCommand(CSMSCLI CLI) : ACLICommand<CSMSCLI>(CLI),
                                                 ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "gateways";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                           : [];

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            var rest   = Arguments.Skip(1).ToArray();

            var needs  = rest.Length == 0
                             ? Permission.Read(CSMSAccess.Stations)
                             : Permission.Edit(CSMSAccess.Stations);

            if (!cli.MayDo(needs, CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            return Task.FromResult(
                       rest switch {
                           []                                                                     => List(),
                           [ var login, var onOff ] when onOff.Equals("on",  StringComparison.OrdinalIgnoreCase) => Mark(login, true),
                           [ var login, var onOff ] when onOff.Equals("off", StringComparison.OrdinalIgnoreCase) => Mark(login, false),
                           _                                                                      => [ $"Usage: {Help()}" ]
                       }
                   );

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [<login> on|off] - the logins of gateways, which may send in the name of the stations behind them";

        #endregion


        #region (private) List() / Mark(Login, Gateway)

        private String[] List()
        {

            var gateways = cli.CSMS.WebSocketLogins.Logins.
                               Where  (login => login.Gateway).
                               OrderBy(login => login.Id, StringComparer.Ordinal).
                               Select (login => $"{login.Id}{(login.Enabled ? "" : " (switched off)")}: " +
                                                (cli.CSMS.IsConnected(login.Id)
                                                     ? cli.CSMS.InOverlayNetwork(login.Id)
                                                           ? "connected, in the overlay network"
                                                           : "connected, in standard mode"
                                                     : "not connected")).
                               ToArray();

            return gateways.Length > 0
                       ? gateways
                       : [ "No login is marked as a gateway's. 'gateways <login> on' marks one." ];

        }

        private String[] Mark(String   Login,
                              Boolean  Gateway)
        {

            var wasAController = Gateway && cli.CSMS.WebSocketLogins.IsLocalController(Login);

            if (!cli.CSMS.WebSocketLogins.TrySetGateway(Login, Gateway, out var error))
                return [ error ];

            cli.Node.Log.Notice(Gateway
                                    ? $"{cli.Caller.Asker} marked '{Login}' as a gateway."
                                    : $"{cli.Caller.Asker} took the mark of a gateway from '{Login}'.",
                                cli.Caller.Tags("ocpp", "station", "security"));

            return [ Gateway
                         ? $"'{Login}' is a gateway now: in the overlay network it may send in the name of the charging stations behind it." +
                           (wasAController ? " It is no local controller any more." : "")
                         : $"'{Login}' is no gateway any more: it sends in its own name alone." ];

        }

        #endregion

    }

}
