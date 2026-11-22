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

using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.OCPI;
using cloud.charging.open.protocols.WWCP.Node.Logging;

using V = cloud.charging.open.protocols.OCPIv2_2_1;

#endregion

namespace cloud.charging.open.CSMS.OCPI
{

    /// <summary>
    /// OCPI 2.2.1, as this charge point operator speaks it.
    /// </summary>
    /// <remarks>
    /// The version most peerings settle on. A party is named by a country
    /// code and a party identification together, several of them can sit
    /// behind one endpoint, and the access tokens travel base64 encoded.
    /// </remarks>
    public sealed class OCPIv2_2_1 : OCPIVersion
    {

        #region Data

        private readonly V.CommonAPI    commonAPI;
        private readonly V.CPO_HTTPAPI  cpoAPI;

        #endregion

        #region Properties

        public override Version_Id  Id
            => V.Version.Id;

        /// <summary>
        /// The library's Common API for this version.
        /// </summary>
        public V.CommonAPI    CommonAPI
            => commonAPI;

        /// <summary>
        /// The library's CPO API for this version.
        /// </summary>
        public V.CPO_HTTPAPI  CPOAPI
            => cpoAPI;

        #endregion

        #region Constructor(s)

        public OCPIv2_2_1(CSMS           CSMS,
                          CommonHTTPAPI  BaseAPI,
                          String         Directory)

            : base(CSMS)

        {

            commonAPI = new V.CommonAPI(

                            OurPartyData:              [
                                                           new V.PartyData(
                                                               CSMS.PartyId,
                                                               Role.CPO,
                                                               CSMS.BusinessDetails,
                                                               CSMS.OCPI.AllowDowngrades
                                                           )
                                                       ],
                            DefaultPartyId:            CSMS.PartyId,

                            BaseAPI:                   BaseAPI,

                            // Only in the URLs it advertises, never in the paths
                            // it serves: see CSMS.OCPI.cs for why.
                            AdditionalURLPathPrefix:   CSMS.ExtAPI.RootPath,

                            HTTPServerName:            $"OpenChargingCloud CSMS v{CSMS.Version}",
                            HTTPServiceName:           $"OpenChargingCloud CSMS v{CSMS.Version}",

                            LoggingPath:               Directory,
                            DisableLogging:            true

                        );

            cpoAPI    = new V.CPO_HTTPAPI(

                            CommonAPI:                 commonAPI,
                            AllowDowngrades:           CSMS.OCPI.AllowDowngrades,

                            HTTPServerName:            $"OpenChargingCloud CSMS v{CSMS.Version}",
                            HTTPServiceName:           $"OpenChargingCloud CSMS v{CSMS.Version}",

                            LoggingPath:               Directory,
                            DisableLogging:            true

                        );

            WireEvents();

        }

        #endregion

        #region (private) WireEvents()

        /// <summary>
        /// What of this version ends up in the event log.
        /// </summary>
        private void WireEvents()
        {

            var log = CSMS.Log;

            #region The credentials handshake

            commonAPI.OnPostCredentialsHTTPResponse   += new V.OCPIResponseLogHandler((timestamp, api, request, response, cancellationToken) => {
                LogHandshake("registered with", request, response);
                return Task.CompletedTask;
            });

            commonAPI.OnPutCredentialsHTTPResponse    += new V.OCPIResponseLogHandler((timestamp, api, request, response, cancellationToken) => {
                LogHandshake("renewed its registration with", request, response);
                return Task.CompletedTask;
            });

            commonAPI.OnDeleteCredentialsHTTPResponse += new V.OCPIResponseLogHandler((timestamp, api, request, response, cancellationToken) => {
                LogHandshake("unregistered from", request, response);
                return Task.CompletedTask;
            });

            #endregion

            #region A line the file of the partners refused

            // The change is taken back - or, a registration a partner accepted,
            // kept and written down later. The file, why and the command; not
            // the line, which holds tokens.
            commonAPI.OnRemotePartyNotSaved += (timestamp, command, fileName, exception) => {
                log.Exception(exception, $"OCPI {Label}: '{fileName}' could not be written ({command})", "ocpi", "files");
                return Task.CompletedTask;
            };

            #endregion

            #region What the partners push

            // The mirror image of the EMSP side: what arrives here are the
            // tokens of somebody else's customers, and what leaves are this
            // operator's locations.
            commonAPI.OnTokenStatusAdded    += tokenStatus => { LogToken(tokenStatus, "pushed");  return Task.CompletedTask; };
            commonAPI.OnTokenStatusChanged  += tokenStatus => { LogToken(tokenStatus, "changed"); return Task.CompletedTask; };

            #endregion


            void LogHandshake(String What, V.OCPIRequest Request, V.OCPIResponse Response)
            {

                var who     = Request.RemoteParty?.Id.ToString() ?? $"somebody at {Request.HTTPRequest.RemoteSocket}";
                var worked  = Response.StatusCode == StatusCode.Success;

                if (CSMS.OCPI.Logging?.Requests == false && worked)
                    return;

                log.Log(
                    worked ? LogLevel.Notice : LogLevel.Warning,
                    worked
                        ? $"The roaming partner {who} {What} this operator (OCPI 2.2.1)."
                        : $"The roaming partner {who} tried to {What.Split(' ')[0]} this operator and was answered {Response.StatusCode}: {Response.StatusMessage} (OCPI 2.2.1).",
                    "ocpi", "credentials", "partner"
                );

            }

            void LogToken(V.TokenStatus TokenStatus, String How)
            {

                if (CSMS.OCPI.Logging?.Requests == false)
                    return;

                log.Info(
                    $"The token '{TokenStatus.Token.Id}' of {TokenStatus.Token.CountryCode}-{TokenStatus.Token.PartyId} was {How} (OCPI 2.2.1).",
                    "ocpi", "tokens", "partner"
                );

            }

        }

        #endregion


        #region Roaming partners

        public override IEnumerable<RemoteParty_Id> UnsavedRemoteParties
            => commonAPI.UnsavedRemoteParties;


        public override IEnumerable<RemotePartySummary> RemoteParties

            => commonAPI.RemoteParties.Select(party => {

                   var roles = party.Roles.ToArray();
                   var role  = roles.Length > 0 ? roles[0] : (CredentialsRole?) null;

                   return Summarize(
                              party,
                              role?.PartyId.CountryCode ?? party.Id.CountryCode,
                              role?.PartyId.PartyId     ?? party.Id.PartyId,
                              role?.Role                ?? party.Id.Role,
                              role?.BusinessDetails     ?? new BusinessDetails(party.Id.ToString())
                          );

               });


        public override async Task<OCPIOperationResult> AddRemoteParty(RemotePartySpec Spec)
        {

            var roles = new[] {
                            new CredentialsRole(
                                Spec.CountryCode,
                                Spec.PartyId,
                                Spec.Role,
                                new BusinessDetails(Spec.Name, Spec.Website),
                                AllowDowngrades: false
                            )
                        };

            var result = Spec.CanRegister

                             ? await commonAPI.AddRemoteParty(
                                         Id:                                Spec.Id,
                                         CredentialsRoles:                  roles,
                                         LocalAccessToken:                  Spec.OurToken,
                                         RemoteVersionsURL:                 Spec.TheirVersionsURL!.Value,
                                         RemoteAccessToken:                 Spec.TheirToken!.Value,
                                         RemoteAccessTokenBase64Encoding:   true,
                                         LocalAccessStatus:                 AccessStatus.ALLOWED,
                                         RemoteStatus:                      RemoteAccessStatus.ONLINE,
                                         Status:                            PartyStatus.ENABLED
                                     )

                             : await commonAPI.AddRemoteParty(
                                         Id:                                Spec.Id,
                                         CredentialsRoles:                  roles,
                                         LocalAccessToken:                  Spec.OurToken,
                                         LocalAccessStatus:                 AccessStatus.ALLOWED,
                                         Status:                            PartyStatus.ENABLED
                                     );

            return result.IsSuccess
                       ? OCPIOperationResult.Ok($"The roaming partner '{Spec.Id}' was added on OCPI {Label}.")
                       : OCPIOperationResult.Failed(
                             result.ErrorResponse ?? "The library declined to add the roaming partner and did not say why.",
                             result.NotSaved
                         );

        }


        public override async Task<OCPIOperationResult> RemoveRemoteParty(RemoteParty_Id Id)
        {

            var result = await commonAPI.TryRemoveRemoteParty(Id);

            return result.IsSuccess
                       ? OCPIOperationResult.Ok($"The roaming partner '{Id}' was removed from OCPI {Label}.")
                       : OCPIOperationResult.Failed(
                             result.ErrorResponse ?? "The library declined to remove the roaming partner and did not say why.",
                             result.NotSaved
                         );

        }


        public override async Task<OCPIOperationResult> Register(RemoteParty_Id Id)
        {

            if (!commonAPI.TryGetRemoteParty(Id, out var party))
                return OCPIOperationResult.Failed($"There is no roaming partner '{Id}' on OCPI 2.2.1.");

            var client = cpoAPI.GetEMSPClient(party, AllowCachedClients: false);

            if (client is null)
                return OCPIOperationResult.Failed($"'{Id}' has not handed out a token and a versions URL, so there is nowhere to send this operator's credentials.");

            var result = await client.TryRegister();

            var outcome = DescribeRegistration(
                              Id,
                              result.Response.StatusCode,
                              result.Response.StatusMessage,
                              result.Response.Data is not null,
                              result.NotSaved,
                              result.Reason
                          );

            // Registered: now the partner can be told this operator's locations.
            if (outcome.Success)
                await PushAllLocations();

            return outcome;

        }

        #endregion

        #region What this operator publishes

        public override IEnumerable<JObject> Locations
            => commonAPI.GetLocations(CSMS.PartyId).Select(location => WithVersion(location.ToJSON()));

        public override IEnumerable<JObject> Tariffs
            => commonAPI.GetTariffs  (CSMS.PartyId).Select(tariff   => WithVersion(tariff.  ToJSON()));

        public override IEnumerable<JObject> Sessions
            => commonAPI.GetSessions (CSMS.PartyId).Select(session  => WithVersion(session. ToJSON()));

        public override IEnumerable<JObject> CDRs
            => commonAPI.GetCDRs     (CSMS.PartyId).Select(cdr      => WithVersion(cdr.     ToJSON()));


        public override Boolean HasLocation(Location_Id Id)
            => commonAPI.GetLocations(CSMS.PartyId).Any(location => location.Id == Id);


        public override async Task<String?> AddLocation(LocationSpec Spec)
        {

            var result = await commonAPI.AddLocation(
                                   new V.Location(
                                       CSMS.PartyId.CountryCode,
                                       CSMS.PartyId.PartyId,
                                       Spec.Id,
                                       Spec.Publish,
                                       Spec.Address,
                                       Spec.City,
                                       Spec.Country,
                                       Spec.Coordinates,
                                       Spec.TimeZone,
                                       Name:        Spec.Name,
                                       PostalCode:  Spec.PostalCode,
                                       Operator:    CSMS.BusinessDetails
                                   )
                               );

            if (!result.IsSuccess)
                return result.ErrorResponse ?? "The library declined to add the location and did not say why.";

            await PushToPartners(Spec.Id);

            return null;

        }


        public override async Task<Boolean> RemoveLocation(Location_Id Id)
        {

            var location = commonAPI.GetLocations(CSMS.PartyId).FirstOrDefault(location => location.Id == Id);

            if (location is null)
                return false;

            var result = await commonAPI.RemoveLocation(location);

            return result.IsSuccess;

        }

        #endregion

        #region (private) PushToPartners(Id) / PushAllLocations()

        /// <summary>
        /// Send a location of this operator to every roaming partner there is
        /// a way to: an EMSP has to know a place before its drivers can find
        /// it, or charge there.
        /// </summary>
        /// <remarks>
        /// Locations were published here, and no partner ever heard of them:
        /// the library has the PUT of the OCPI locations module for an EMSP,
        /// and nothing called it. A partner that cannot be reached, or
        /// declines the location, is said in the log and does not undo what
        /// was done here: it is sent everything again when it is registered
        /// with. A location taken away here is not taken back from a partner,
        /// because OCPI has no way to: it would have to be marked as removed.
        /// </remarks>
        private async Task PushToPartners(Location_Id Id)
        {

            if (commonAPI.GetLocations(CSMS.PartyId).FirstOrDefault(location => location.Id == Id) is not { } location)
                return;

            foreach (var party in commonAPI.RemoteParties.ToArray())
            {

                var client = cpoAPI.GetEMSPClient(party);

                // No token and no versions URL of theirs yet: nowhere to send it.
                if (client is null)
                    continue;

                try
                {

                    var response = await client.PutLocation(location);

                    if (response.StatusCode == StatusCode.Success)
                        CSMS.Log.Info   ($"The location '{Id}' was sent to '{party.Id}' on OCPI {Label}.", "ocpi", "locations", "partner");
                    else
                        CSMS.Log.Warning($"The location '{Id}' was not taken by '{party.Id}' on OCPI {Label}: {response.StatusCode} {response.StatusMessage}", "ocpi", "locations", "partner");

                }
                catch (Exception e)
                {
                    CSMS.Log.Warning($"The location '{Id}' could not be sent to '{party.Id}' on OCPI {Label}: {e.Message}", "ocpi", "locations", "partner");
                }

            }

        }

        /// <summary>
        /// Send every location of this operator to its roaming partners: after
        /// a registration, which is when a partner first can be told.
        /// </summary>
        private async Task PushAllLocations()
        {
            foreach (var id in commonAPI.GetLocations(CSMS.PartyId).Select(location => location.Id).ToArray())
                await PushToPartners(id);
        }

        #endregion

        #region What the partners sent

        public override IEnumerable<JObject> Tokens

            => commonAPI.GetTokenStatus().
                         Select(tokenStatus => WithVersion(
                                                   tokenStatus.Token.ToJSON(),
                                                   new JProperty("status", tokenStatus.Status.ToString())
                                               ));

        #endregion

        #region Modules

        protected override IEnumerable<String> Modules
            => [ "locations", "tariffs", "sessions", "cdrs", "tokens", "commands" ];

        #endregion

    }

}
