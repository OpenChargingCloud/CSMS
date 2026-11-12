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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;

using cloud.charging.open.protocols.OCPPv2_1;
using cloud.charging.open.protocols.OCPPv2_1.CS;
using cloud.charging.open.protocols.OCPPv2_1.CSMS;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// A charging station's Authorize request, answered with what this
    /// operator knows of the card: the tokens its roaming partners pushed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The OCPP node answers an Authorize by itself with a list of tokens
    /// nothing in this CSMS fills, and with three tokens it accepts for
    /// testing - so every station was told "Invalid" of every real card, and
    /// "Accepted" of three that are nobody's. This takes its place.
    /// </para>
    /// <para>
    /// The cards this operator knows are the ones its roaming partners sent
    /// over OCPI: nothing here issues a token, as a token this operator made
    /// up would be a card nobody is billed for (see OCPIVersion.Tokens). A
    /// card is accepted where a partner's token of that uid is valid, is
    /// allowed, and may be decided on here; what else a partner says of it -
    /// blocked, expired, no credit - is what the station is told.
    /// </para>
    /// <para>
    /// A token whose whitelist is NEVER is the partner's to decide on at the
    /// moment it is used, and this CSMS does not ask a partner yet: such a
    /// card is turned away, and the log says that this is why.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// How long a charging station may go by the answer it was given,
        /// without asking again.
        /// </summary>
        public static readonly TimeSpan  AuthorizationCacheTime  = TimeSpan.FromMinutes(15);

        #endregion


        #region (private) BuildAuthorization()

        /// <summary>
        /// Have Authorize requests answered with the tokens of the roaming
        /// partners - and not by the stand-in of the OCPP node.
        /// </summary>
        private void BuildAuthorization()
        {
            csms01.AuthorizeProcessor = Authorize;
        }

        #endregion

        #region AuthorizationOf(UID)

        /// <summary>
        /// What this operator says of a card: "Accepted", or the OCPP
        /// authorization status that says why not.
        /// </summary>
        /// <param name="UID">The card's UID, as a reader reads it.</param>
        /// <returns>The status, and who the card is of, where a partner's token says so.</returns>
        public (AuthorizationStatus Status, String? Partner, String? Why) AuthorizationOf(String UID)
        {

            var tokens = ocpiVersions.
                             SelectMany(version => version.Tokens).
                             Where     (token   => String.Equals(token.Value<String>("uid"), UID, StringComparison.OrdinalIgnoreCase)).
                             ToArray   ();

            if (tokens.Length == 0)
                return (AuthorizationStatus.Unknown, null, "no roaming partner sent a token of that uid");

            (AuthorizationStatus Status, String? Partner, String? Why)? refusal = null;

            // Two partners' cards of the same uid are two cards: it charges
            // where one of them lets it.
            foreach (var token in tokens)
            {

                // OCPI 2.1.1 has the party in the URL and not in the token.
                var partner = token.Value<String>("party_id") is String partyId
                                  ? $"{token.Value<String>("country_code")}*{partyId}"
                                  : $"a roaming partner (OCPI {token.Value<String>("version")})";

                var (status, why) = token switch {

                    _ when token.Value<Boolean?>("valid") == false
                        => (AuthorizationStatus.Invalid,  "its token is not valid"),

                    _ when token.Value<String>("whitelist") == "NEVER"
                        => (AuthorizationStatus.Unknown,  "its token is the partner's to decide on when it is used (whitelist NEVER), and this CSMS does not ask a partner yet"),

                    _   => token.Value<String>("status") switch {
                               "ALLOWED" or null  => (AuthorizationStatus.Accepted,  (String?) null),
                               "BLOCKED"          => (AuthorizationStatus.Blocked,   "its token is blocked"),
                               "EXPIRED"          => (AuthorizationStatus.Expired,   "its token has expired"),
                               "NO_CREDIT"        => (AuthorizationStatus.NoCredit,  "its token has no credit"),
                               var other          => (AuthorizationStatus.Invalid,   $"its token is '{other}'")
                           }

                };

                if (status == AuthorizationStatus.Accepted)
                    return (status, partner, null);

                refusal ??= (status, partner, why);

            }

            return refusal!.Value;

        }

        #endregion

        #region (private) Authorize(Timestamp, Sender, Connection, Request, CancellationToken)

        /// <summary>
        /// A charging station's Authorize request, answered with what the
        /// roaming partners said of the card.
        /// </summary>
        private Task<AuthorizeResponse> Authorize(DateTimeOffset      Timestamp,
                                                  IEventSender        Sender,
                                                  IMessageConnection  Connection,
                                                  AuthorizeRequest    Request,
                                                  CancellationToken   CancellationToken)
        {

            var station                 = Request.NetworkPath.Source.ToString();
            var uid                     = Request.IdToken.Value.ToString();
            var (status, partner, why)  = AuthorizationOf(uid);

            if (status == AuthorizationStatus.Accepted)
                Log.Info  ($"The card {Masked(uid)} at '{station}' was accepted: a token of {partner}.", "ocpp", "authorization", "station");
            else
                Log.Notice($"The card {Masked(uid)} at '{station}' was turned away ({status}): " +
                           (partner is null ? why : $"{partner} - {why}") + ".",
                           "ocpp", "authorization", "station");

            return Task.FromResult(
                       new AuthorizeResponse(
                           Request:      Request,
                           IdTokenInfo:  new IdTokenInfo(
                                             Status:               status,
                                             CacheExpiryDateTime:  TimeProvider.GetUtcNow().Add(AuthorizationCacheTime)
                                         )
                       )
                   );

        }

        #endregion

        #region (private static) Masked(UID)

        /// <summary>
        /// A UID for the log: its last four characters, which tell two cards
        /// apart and are not the card.
        /// </summary>
        private static String Masked(String UID)

            => UID.Length <= 4
                   ? new String('*', UID.Length)
                   : new String('*', UID.Length - 4) + UID[^4..];

        #endregion

    }

}
