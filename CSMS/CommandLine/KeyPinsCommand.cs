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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS.CommandLine
{

    /// <summary>
    /// The key pins of the charging stations behind the local controllers (white paper "Key Pins and TLS 1.3
    /// Raw Public Keys for Local Controllers", sections 5.5 to 5.7): listed, confirmed, rolled over - and the
    /// key the pin sets are signed with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// keyPins lists every local controller with the key pins last read of it and the stations behind it;
    /// keyPins show &lt;controller&gt; one controller; keyPins rollover &lt;controller&gt; [grace] rolls it over to
    /// its announced next key - every station handed [current, next], each asked whether it has the next pin,
    /// the controller switched only then, and after the grace period - seconds, or 30s, 5m, 1h; 0 for at once
    /// - every station handed [next]; keyPins confirm &lt;station|controller&gt; hands a station, or every station
    /// behind a controller, the controller's pins as it reports them now; keyPins forget &lt;station&gt; forgets the
    /// controller a station that moved was behind, and the route through it, so that its next BootNotification
    /// notes it behind the controller it comes through. keyPins signer shows the public key of
    /// the signing key, in the form a station's pin set signers take it; keyPins signer create makes it.
    /// </para>
    /// <para>
    /// Looking is at the stations' permission, as the page of the certificate signing reads; everything that
    /// changes whom a station believes - a pin set, a switch, the signing key, where a station's pin sets go -
    /// is at the certificates', which
    /// only the administrators have. The console may do everything.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line.</param>
    public class KeyPinsCommand(CSMSCLI CLI) : ACLICommand<CSMSCLI>(CLI),
                                                ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "keyPins";

        private static readonly String[] Verbs = [ "list", "show", "rollover", "confirm", "uplink", "forget", "signer" ];

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)
        {

            if (Arguments.Length == 1)
                return CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                           : [];

            if (Arguments.Length == 2 && String.Equals(Arguments[0], CommandName, StringComparison.OrdinalIgnoreCase))
                return Verbs.Where (verb => verb.StartsWith(Arguments[1], StringComparison.OrdinalIgnoreCase)).
                             Select(verb => SuggestionResponse.ParameterCompleted($"{CommandName} {verb}"));

            return [];

        }

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            var rest  = Arguments.Skip(1).ToArray();
            var verb  = rest.Length == 0 ? "list" : rest[0].ToLowerInvariant();

            var needs = verb switch {
                            "rollover"                                            => Permission.Edit(NodeResources.Certificates),
                            "confirm"                                             => Permission.Edit(NodeResources.Certificates),
                            "uplink"                                              => Permission.Edit(NodeResources.Certificates),
                            "forget"                                              => Permission.Edit(NodeResources.Certificates),
                            "signer" when rest.Length > 1 && rest[1] == "create"  => Permission.Edit(NodeResources.Certificates),
                            _                                                     => Permission.Read(CSMSAccess.Stations)
                        };

            if (!cli.MayDo(needs, CommandName, out var refused))
                return [ refused ];

            return verb switch {
                       "list"                                                => List(),
                       "show"     when rest.Length == 2                      => Show(rest[1]),
                       "rollover" when rest.Length is 2 or 3                 => await Rollover(rest[1], rest.Length == 3 ? rest[2] : null, CancellationToken),
                       "confirm"  when rest.Length == 2                      => await Confirm(rest[1], CancellationToken),
                       "uplink"   when rest.Length is 2 or 3                 => await Uplink(rest[1], rest.Length == 3 ? rest[2] : null, CancellationToken),
                       "forget"   when rest.Length == 2                      => Forget(rest[1]),
                       "signer"   when rest.Length == 1                      => Signer(),
                       "signer"   when rest.Length == 2 && rest[1] == "create" => CreateSigner(),
                       _                                                     => [ $"Usage: {Help()}" ]
                   };

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} [list | show <controller> | rollover <controller> [grace] | confirm <station|controller> | uplink <controller> [<pin>[,<pin>...]] | " +
                "forget <station> | signer [create]] - the key pins of the stations behind the local controllers and of the local controllers' own lines " +
                "to this CSMS, and the key their pin sets are signed with";

        #endregion


        #region (private) List() / Show(LocalController)

        private String[] List()
        {

            var lines = new List<String>();

            foreach (var controller in cli.CSMS.KeyPins.All)
                lines.AddRange(Lines(controller));

            if (lines.Count == 0)
                lines.Add("No charging station is known behind a local controller. A station is, once its BootNotification came through " +
                          "its controller, with the controller dialling this CSMS in the overlay network.");

            lines.Add(cli.CSMS.ServerKeyPins() is { Count: > 0 } own
                          ? $"This CSMS presents the key pin {String.Join(", ", own.Select(pin => pin.ToHex()))} at its charging station port."
                          : "This CSMS presents no key of its own at its charging station port: it is not encrypted here.");

            lines.Add(SignerLine());

            return [ .. lines ];

        }

        private String[] Show(String LocalController)

            => cli.CSMS.KeyPins.Get(LocalController) is LocalControllerKeyPins controller
                   ? [ .. Lines(controller) ]
                   : [ $"'{LocalController}' is no local controller this CSMS knows charging stations behind." ];

        /// <summary>
        /// One controller, as lines: its key pins as last read, whether it is connected and in the overlay
        /// network, and each station behind it with the pin set it was last handed.
        /// </summary>
        private IEnumerable<String> Lines(LocalControllerKeyPins Controller)
        {

            var connected  = cli.CSMS.IsConnected     (Controller.LocalController);
            var overlay    = cli.CSMS.InOverlayNetwork(Controller.LocalController);

            yield return $"{Controller.LocalController}: " +
                         (connected ? overlay ? "connected, in the overlay network" : "connected, in standard mode" : "not connected");

            yield return Controller.Read is DateTimeOffset read
                             ? $"  key pins read {read.ToLocalTime():yyyy-MM-dd HH:mm:ss}: current {Controller.CurrentKeyPin ?? "-"}, next {Controller.NextKeyPin ?? "none announced"}" +
                               (Controller.KeyCreated is DateTimeOffset created ? $", current key made {created.ToLocalTime():yyyy-MM-dd}" : "")
                             : "  key pins not read yet";

            if (Controller.Uplink is LocalControllerUplink uplink)
                yield return $"  its own line to this CSMS, endpoint '{uplink.Endpoint ?? "?"}': " +
                             (uplink.LearnedKeyPin is not null
                                  ? $"{uplink.State ?? "?"} - key pin {uplink.LearnedKeyPin} learned on first use" +
                                    (uplink.OursWhenLearned switch {
                                         true   => ", which is this CSMS's",
                                         false  => ", which is NOT this CSMS's",
                                         _      => ", and this CSMS presents no key of its own to compare it with"
                                     })
                                  : uplink.State ?? "nothing reported") +
                             (uplink.Sent is DateTimeOffset uplinkSent
                                  ? $"; {(uplink.Accepted ? "took" : "did not take")} [{String.Join(", ", uplink.Pins ?? [])}] of version " +
                                    $"{uplink.Version?.ToString(CultureInfo.InvariantCulture) ?? "?"} on {uplinkSent.ToLocalTime():yyyy-MM-dd HH:mm:ss}" +
                                    (uplink.Accepted ? "" : $": {uplink.Answer}")
                                  : "; no pin set sent yet");

            foreach (var station in Controller.Stations ?? [])
                yield return $"  {station.Station}: " +
                             (station.Connection is null
                                  ? "no pin set yet"
                                  : $"endpoint '{station.Connection}', version {station.Version?.ToString(CultureInfo.InvariantCulture) ?? "?"}" +
                                    (station.Sent is DateTimeOffset sent
                                         ? $", {(station.Accepted ? "took" : "did not take")} [{String.Join(", ", station.Pins ?? [])}] on {sent.ToLocalTime():yyyy-MM-dd HH:mm:ss}" +
                                           (station.Accepted ? "" : $": {station.Answer}")
                                         : ", nothing sent yet"));

        }

        #endregion

        #region (private) Rollover(LocalController, Grace, CancellationToken)

        private async Task<String[]> Rollover(String             LocalController,
                                              String?            Grace,
                                              CancellationToken  CancellationToken)
        {

            TimeSpan? grace = null;

            if (Grace is not null)
            {

                if (!TryParseGrace(Grace, out var parsed))
                    return [ $"'{Grace}' is no grace period: seconds, or a number with s, m or h - 30, 30s, 5m, 1h; 0 for at once." ];

                grace = parsed;

            }

            cli.Node.Log.Notice($"{cli.Caller.Asker} rolls the local controller '{LocalController}' over to its next key.",
                                cli.Caller.Tags("ocpp", "keypins", "security"));

            var run = await cli.CSMS.RolloverAsync(LocalController, grace, CancellationToken);

            return [ .. run.Said ];

        }

        /// <summary>
        /// A grace period as typed: seconds, or a number with s, m or h.
        /// </summary>
        internal static Boolean TryParseGrace(String Text, out TimeSpan Grace)
        {

            Grace = TimeSpan.Zero;

            var text = Text.Trim().ToLowerInvariant();
            var unit = 's';

            if (text.Length > 0 && Char.IsLetter(text[^1]))
            {
                unit = text[^1];
                text = text[..^1];
            }

            if (!UInt32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value > 10_000_000)
                return false;

            Grace = unit switch {
                        's' => TimeSpan.FromSeconds((Double) value),
                        'm' => TimeSpan.FromMinutes((Double) value),
                        'h' => TimeSpan.FromHours  ((Double) value),
                        _   => TimeSpan.MinValue
                    };

            return Grace >= TimeSpan.Zero && Grace <= CSMS.MaxRolloverGrace;

        }

        #endregion

        #region (private) Confirm(Target, CancellationToken)

        private async Task<String[]> Confirm(String             Target,
                                             CancellationToken  CancellationToken)
        {

            cli.Node.Log.Notice($"{cli.Caller.Asker} hands '{Target}' the key pins of its local controller.",
                                cli.Caller.Tags("ocpp", "keypins", "security"));

            var run = await cli.CSMS.ConfirmAsync(Target, CancellationToken: CancellationToken);

            return [ .. run.Said ];

        }

        #endregion

        #region (private) Uplink(LocalController, Pins, CancellationToken)

        private async Task<String[]> Uplink(String             LocalController,
                                            String?            Pins,
                                            CancellationToken  CancellationToken)
        {

            List<KeyPin>? pins = null;

            if (Pins is not null)
            {

                pins = [];

                foreach (var text in Pins.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {

                    if (!KeyPin.TryParse(text, out var pin))
                        return [ $"'{text}' is no key pin: the SHA-256 of a public key, as 64 hexadecimal digits." ];

                    pins.Add(pin);

                }

                if (pins.Count == 0)
                    return [ $"Usage: {Help()}" ];

            }

            cli.Node.Log.Notice($"{cli.Caller.Asker} hands the local controller '{LocalController}' " +
                                (pins is null ? "this CSMS's key pins" : $"the key pins {String.Join(", ", pins.Select(pin => pin.ToHex()))}") +
                                " for its own line to this CSMS.",
                                cli.Caller.Tags("ocpp", "keypins", "security"));

            var run = await cli.CSMS.ConfirmUplinkAsync(LocalController, pins, CancellationToken: CancellationToken);

            return [ .. run.Said ];

        }

        #endregion

        #region (private) Forget(Station)

        private String[] Forget(String Station)
        {

            if (cli.CSMS.ForgetWhereAStationIs(Station) is not String controller)
                return [ $"'{Station}' is not known behind a local controller." ];

            cli.Node.Log.Notice($"{cli.Caller.Asker} made this CSMS forget that the charging station '{Station}' is behind '{controller}'.",
                                cli.Caller.Tags("ocpp", "keypins", "security"));

            return [ $"'{Station}' is forgotten behind '{controller}': its next BootNotification notes it behind the local controller it comes through." ];

        }

        #endregion

        #region (private) Signer() / CreateSigner() / SignerLine()

        private String[] Signer()

            => cli.CSMS.PinSetSigner.PublicKey is String publicKey
                   ? [ $"The public key of this CSMS's pin sets, as a station's pin set signers take it: {publicKey}",
                       $"Made {cli.CSMS.PinSetSigner.CreatedAt?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "at a time not known"}" +
                       (cli.CSMS.PinSetSigner.CreatedBy is String by ? $" by {by}" : "") + $", kept in '{cli.CSMS.PinSetSigner.Path}'." ]
                   : [ "This CSMS has no signing key for pin sets. 'keyPins signer create' makes one." ];

        private String[] CreateSigner()
        {

            var by = cli.Caller.Account?.Id.ToString() ?? "the console";

            if (!cli.CSMS.PinSetSigner.TryCreate(by, out var publicKey, out var error))
                return [ error ];

            cli.Node.Log.Notice($"{cli.Caller.Asker} made the signing key for pin sets; its public key is {publicKey}.",
                                cli.Caller.Tags("ocpp", "keypins", "security"));

            return [ $"The signing key for pin sets is made. Give the charging stations its public key as a pin set signer, at commissioning:",
                     publicKey ];

        }

        private String SignerLine()

            => cli.CSMS.PinSetSigner.PublicKey is String publicKey
                   ? $"Pin sets are signed with the key {publicKey}."
                   : "This CSMS has no signing key for pin sets: 'keyPins signer create' makes one.";

        #endregion

    }

}
