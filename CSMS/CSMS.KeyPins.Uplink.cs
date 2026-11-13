/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP CSMS <https://github.com/OpenChargingCloud/CSMS>
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

using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP.Node.Logging;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The key pin a Local Controller learned of this CSMS on its own line (white paper "Key Pins and TLS 1.3 Raw
    /// Public Keys for Local Controllers", sections 5.6 and 5.7, one level up): a controller that trusts on first
    /// use reports KeyPinLearned as a charging station does, and executes nothing but a signed pin set until one
    /// confirms what it learned.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Whose key it learned</b> is something this CSMS can say itself, unlike with a station behind a
    /// controller: the key is its own. Where the key pin learned is the pin of the key this CSMS presents at its
    /// charging station port, the controller is handed that pin in a signed pin set at once.
    /// </para>
    /// <para>
    /// <b>Where it is not</b> - TLS ends at a proxy in front of this CSMS, or somebody answered the controller's
    /// first handshake in its place - nothing is sent: the key pin is shown beside this CSMS's own, and whoever
    /// runs this CSMS names the pins the controller is to hold, having compared them with the key of what ends
    /// TLS. A pin set that does not have the learned key pin makes the controller refuse the server it learned
    /// it of.
    /// </para>
    /// <para>
    /// The pin set is one SetVariables of the controller's TLSClientController[&lt;endpoint&gt;], as a station's is,
    /// addressed to the controller itself and signed with <see cref="PinSetSigner"/>, whose public key the
    /// controller holds as one of its pin set signers.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// The security event of a key that is not the pinned one, and what its techInfo begins with.
        /// </summary>
        public const  String  InvalidCsmsCertificate  = "InvalidCsmsCertificate";
        public const  String  KeyPinMismatch          = "Key pin mismatch";

        /// <summary>
        /// "Key pin &lt;hex&gt; of endpoint '&lt;id&gt;' (&lt;url&gt;) ...", as KeyPinLearned says it.
        /// </summary>
        private static readonly Regex  keyPinLearnedOf   = new (@"Key pin (\S+) of endpoint '([^']+)'(?: \(([^)]*)\))?", RegexOptions.CultureInvariant);

        /// <summary>
        /// "Key pin mismatch: &lt;hex&gt; at endpoint '&lt;id&gt;' ...", as InvalidCsmsCertificate says it.
        /// </summary>
        private static readonly Regex  keyPinMismatchAt  = new (@"Key pin mismatch: (\S+) at endpoint '([^']+)'", RegexOptions.CultureInvariant);

        /// <summary>
        /// The key pins this CSMS presents, where a test says them.
        /// </summary>
        internal Func<IReadOnlyList<KeyPin>>?  ServerKeyPinsForTests;

        #endregion


        #region ServerKeyPins()

        /// <summary>
        /// The key pins of the key this CSMS presents at its charging station port: of the certificate it
        /// chooses now - or none, where that port is not encrypted here.
        /// </summary>
        public IReadOnlyList<KeyPin> ServerKeyPins()
        {

            if (ServerKeyPinsForTests is not null)
                return ServerKeyPinsForTests();

            try
            {
                return ocppServerTLS && ServerCertificates.Select() is ServerCertificateChain chain
                           ? [ KeyPin.FromCertificate(chain.Certificate) ]
                           : [];
            }
            catch (Exception e)
            {
                Log.Exception(e, "The key pin of this CSMS's own key could not be had.", "ocpp", "keypins", "tls");
                return [];
            }

        }

        #endregion

        #region (private) OnUplinkKeyPinEvent(LocalController, Type, TechInfo)

        /// <summary>
        /// A security event of a key pin that a Local Controller sent over its own line, in its own name: noted,
        /// said, and - a key pin learned that is this CSMS's own - confirmed.
        /// </summary>
        /// <returns>Whether it was one: of a login marked as a local controller's, and about a key pin of its own line.</returns>
        private Boolean OnUplinkKeyPinEvent(String  LocalController,
                                            String  Type,
                                            String  TechInfo)
        {

            if (!StationLogins.IsLocalController(LocalController))
                return false;

            var now = TimeProvider.GetUtcNow();

            switch (Type)
            {

                case KeyPinLearned:

                    var learnedOf  = keyPinLearnedOf.Match(TechInfo);

                    if (!learnedOf.Success || !KeyPin.TryParse(learnedOf.Groups[1].Value, out var learned))
                    {
                        Log.Warning($"The local controller '{LocalController}' learned a key pin of this CSMS on first use, and its event does not say " +
                                    $"which: {TechInfo}", "ocpp", "keypins", "security");
                        return true;
                    }

                    var endpoint   = learnedOf.Groups[2].Value;
                    var own        = ServerKeyPins();
                    Boolean? ours  = own.Count == 0 ? null : own.Contains(learned);

                    KeyPins.NoteUplink(LocalController, uplink => uplink with {
                                                                      Endpoint         = endpoint,
                                                                      URL              = learnedOf.Groups[3].Success ? learnedOf.Groups[3].Value : uplink.URL,
                                                                      LearnedKeyPin    = learned.ToHex(),
                                                                      Reported         = now,
                                                                      State            = LocalControllerUplink.Learned,
                                                                      OursWhenLearned  = ours
                                                                  });

                    switch (ours)
                    {

                        case true when PinSetSigner.Exists:
                            Log.Notice ($"The local controller '{LocalController}' learned the key pin {learned} of this CSMS on first use, which is this " +
                                        "CSMS's own, and waits for a signed pin set.",
                                        "ocpp", "keypins", "security");
                            _ = Task.Run(() => ConfirmLearnedUplinkKeyPin(LocalController, endpoint));
                            break;

                        case true:
                            Log.Warning($"The local controller '{LocalController}' learned the key pin {learned} of this CSMS on first use, which is this " +
                                        "CSMS's own - and is not sent a pin set to confirm it: this CSMS has no signing key for pin sets. Make one with " +
                                        "'keyPins signer create', give its public key to the local controller as a pin set signer, and confirm with " +
                                        $"'keyPins uplink {LocalController}' before its probation runs out.",
                                        "ocpp", "keypins", "security");
                            break;

                        case false:
                            Log.Warning($"The local controller '{LocalController}' learned the key pin {learned} on first use, which is NOT the key pin of " +
                                        $"the key this CSMS presents ({String.Join(", ", own)}): TLS ends before this CSMS, or somebody answered " +
                                        "the local controller in its place. No pin set is sent. Compare the key pin with the key of what ends TLS, and " +
                                        $"name the pins the local controller is to hold: 'keyPins uplink {LocalController} <pin>[,<pin>...]'.",
                                        "ocpp", "keypins", "security");
                            break;

                        default:
                            Log.Warning($"The local controller '{LocalController}' learned the key pin {learned} on first use, and this CSMS presents no " +
                                        "key of its own to compare it with: its charging station port is not encrypted here. No pin set is sent. Compare " +
                                        "the key pin with the key of what ends TLS, and name the pins the local controller is to hold: " +
                                        $"'keyPins uplink {LocalController} <pin>[,<pin>...]'.",
                                        "ocpp", "keypins", "security");
                            break;

                    }

                    return true;

                case KeyPinConfirmed:
                    KeyPins.NoteUplink(LocalController, uplink => uplink with { Reported = now, State = LocalControllerUplink.Confirmed });
                    Log.Notice ($"The local controller '{LocalController}' confirmed the key pin it learned of this CSMS: {TechInfo}",
                                "ocpp", "keypins", "security");
                    return true;

                case KeyPinRejected:
                    KeyPins.NoteUplink(LocalController, uplink => uplink with { Reported = now, State = LocalControllerUplink.Rejected });
                    Log.Warning($"The local controller '{LocalController}' refused the server it learned a key pin of - the signed pins do not have " +
                                $"it - and is held to them: {TechInfo}", "ocpp", "keypins", "security");
                    return true;

                case KeyPinProbationExpired:
                    KeyPins.NoteUplink(LocalController, uplink => uplink with { Reported = now, State = LocalControllerUplink.Expired });
                    Log.Warning($"The local controller '{LocalController}' got no signed pin set in time and forgot the key pin it learned of this " +
                                $"CSMS: {TechInfo}", "ocpp", "keypins", "security");
                    return true;

                case InvalidCsmsCertificate when TechInfo.StartsWith(KeyPinMismatch, StringComparison.Ordinal):

                    var mismatchAt = keyPinMismatchAt.Match(TechInfo);

                    KeyPins.NoteUplink(LocalController, uplink => uplink with {
                                                                      Endpoint  = mismatchAt.Success ? mismatchAt.Groups[2].Value : uplink.Endpoint,
                                                                      Reported  = now,
                                                                      State     = LocalControllerUplink.Mismatch
                                                                  });

                    Log.Warning($"The local controller '{LocalController}' was shown a key that is not one it holds a key pin of: {TechInfo}",
                                "ocpp", "keypins", "security");
                    return true;

                default:
                    return false;

            }

        }

        #endregion

        #region (private) ConfirmLearnedUplinkKeyPin(LocalController, Endpoint)

        private async Task ConfirmLearnedUplinkKeyPin(String  LocalController,
                                                      String  Endpoint)
        {

            try
            {

                var run = await ConfirmUplinkAsync(LocalController, Named: Endpoint);

                foreach (var line in run.Said)
                    Log.Log(run.Done ? LogLevel.Info : LogLevel.Warning, line, "ocpp", "keypins", "security");

            }
            catch (Exception e)
            {
                Log.Exception(e, $"The key pin '{LocalController}' learned of this CSMS could not be confirmed.", "ocpp", "keypins", "security");
            }

        }

        #endregion

        #region ConfirmUplinkAsync(LocalController, Pins = null, Named = null, CancellationToken = default)

        /// <summary>
        /// Hand a Local Controller a signed pin set for its own line to this CSMS: the key pins this CSMS
        /// presents itself, or the given ones, with a version above the one the controller holds.
        /// </summary>
        /// <remarks>
        /// Without pins given, this CSMS's own - and only where the key pin the controller learned is among
        /// them, or it learned none: what it learned of somebody else is not answered with a pin set nobody
        /// looked at. With pins given, those, whatever the controller learned: a controller whose learned key
        /// pin is not among them refuses the server it learned it of, and dials again.
        /// </remarks>
        /// <param name="LocalController">A login marked as a local controller's.</param>
        /// <param name="Pins">The key pins the controller is to hold; this CSMS's own where null.</param>
        /// <param name="Named">The endpoint the controller named in its KeyPinLearned, where it did.</param>
        /// <param name="CancellationToken">To stop while waiting for another run of the same controller.</param>
        public async Task<KeyPinRun> ConfirmUplinkAsync(String                  LocalController,
                                                        IReadOnlyList<KeyPin>?  Pins                = null,
                                                        String?                 Named               = null,
                                                        CancellationToken       CancellationToken   = default)
        {

            var controller = LocalController.Trim();

            if (!StationLogins.IsLocalController(controller))
                return Refused($"'{controller}' is no login marked as a local controller's: 'localControllers {controller} on' marks it.");

            if (!PinSetSigner.Exists)
                return Refused("This CSMS has no signing key for pin sets, and a local controller takes no pin set it did not sign. Make one with " +
                               "'keyPins signer create' and give its public key to the local controller as a pin set signer.");

            if (!IsConnected(controller))
                return Refused($"The local controller '{controller}' is not connected.");

            var known  = KeyPins.Get(controller)?.Uplink;
            var own    = ServerKeyPins();
            var pins   = Pins ?? own;

            if (pins.Count == 0)
                return Refused("This CSMS presents no key of its own at its charging station port - it is not encrypted here - so it has no key pins " +
                               $"to hand '{controller}'. Name the pins it is to hold: 'keyPins uplink {controller} <pin>[,<pin>...]'.");

            if (Pins is null &&
                known?.State == LocalControllerUplink.Learned &&
                KeyPin.TryParse(known.LearnedKeyPin, out var learned) &&
                !own.Contains(learned))
            {
                return Refused($"'{controller}' learned the key pin {learned}, which is not the key pin of the key this CSMS presents " +
                               $"({String.Join(", ", own)}): TLS ends before this CSMS, or somebody answered the local controller in its place. " +
                               $"Name the pins it is to hold: 'keyPins uplink {controller} <pin>[,<pin>...]'.");
            }

            var runLock = keyPinRuns.GetOrAdd(controller, _ => new SemaphoreSlim(1, 1));

            await runLock.WaitAsync(CancellationToken);

            try
            {

                var hex  = pins.Select(pin => pin.ToHex()).ToArray();
                var said = new List<String>();

                var (endpoints, problem) = await ReadEndpointsAsync(controller);

                if (problem is not null)
                    return new KeyPinRun(false, [ $"'{controller}' does not have the pins {String.Join(", ", hex)}: {problem}." ],
                                         [ new PinSetOutcome(controller, null, null, hex, false, problem) ]);

                var endpoint = ChooseUplinkEndpoint(endpoints!, Named ?? known?.Endpoint);

                if (endpoint is null)
                {

                    var why = endpoints!.Count == 0
                                  ? "it has no endpoint over TLS"
                                  : $"none of its {endpoints.Count} endpoints over TLS ({String.Join(", ", endpoints.Select(endpoint => endpoint.Connection))}) " +
                                     "can be told to lead to this CSMS: none is the one it named, and not exactly one is on probation";

                    return new KeyPinRun(false, [ $"'{controller}' does not have the pins {String.Join(", ", hex)}: {why}." ],
                                         [ new PinSetOutcome(controller, null, null, hex, false, why) ]);

                }

                if (endpoint.Learned is KeyPin onProbation && !pins.Contains(onProbation))
                    said.Add($"The pins do not have the key pin {onProbation} that '{controller}' learned on first use: it will refuse the server it " +
                              "learned it of, and dial again.");

                var outcome = await SendPinSet(controller, endpoint.Connection, pins, endpoint.Version + 1, "local controller");

                KeyPins.NoteUplink(controller, uplink => uplink with {
                                                             Endpoint  = endpoint.Connection,
                                                             Version   = outcome.Version,
                                                             Pins      = hex,
                                                             Sent      = TimeProvider.GetUtcNow(),
                                                             Answer    = outcome.Answer,
                                                             Accepted  = outcome.Accepted
                                                         });

                said.Add(Said(outcome));

                return new KeyPinRun(outcome.Accepted, said, [ outcome ]);

            }
            finally
            {
                runLock.Release();
            }

        }

        #endregion

        #region (internal static) ChooseUplinkEndpoint(Endpoints, Named)

        /// <summary>
        /// The endpoint of a Local Controller that leads to this CSMS: the one it named; or, where it named
        /// none, the only one on probation; or the only one there is.
        /// </summary>
        internal static StationEndpoint? ChooseUplinkEndpoint(IReadOnlyList<StationEndpoint>  Endpoints,
                                                              String?                         Named)
        {

            if (Named is not null)
                return Endpoints.FirstOrDefault(endpoint => endpoint.Connection == Named);

            var onProbation = Endpoints.Where(endpoint => endpoint.State == "Learned" || endpoint.Learned is not null).ToArray();

            return onProbation.Length == 1
                       ? onProbation[0]
                       : Endpoints.Count == 1
                             ? Endpoints[0]
                             : null;

        }

        #endregion

    }

}
