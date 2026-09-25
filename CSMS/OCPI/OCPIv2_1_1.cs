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

using V = cloud.charging.open.protocols.OCPIv2_1_1;

#endregion

namespace cloud.charging.open.CSMS.OCPI
{

    /// <summary>
    /// OCPI 2.1.1, as this charge point operator speaks it: the classic one,
    /// with one party per peer and a location that says what kind of place it
    /// is.
    /// </summary>
    /// <remarks>
    /// This version has no notion of several parties behind one endpoint, so
    /// the library's Common API for it is built for exactly one - this
    /// operator - and a remote party is a country code, a party identification
    /// and a role rather than a list of credentials roles. Tokens are sent to
    /// the partner unencoded, which is why the remote token is not base64
    /// encoded here where it is in the versions after it.
    /// </remarks>
    public sealed class OCPIv2_1_1 : OCPIVersion
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

        public OCPIv2_1_1(CSMS           CSMS,
                          CommonHTTPAPI  BaseAPI,
                          String         Directory)

            : base(CSMS)

        {

            commonAPI = new V.CommonAPI(

                            OurBusinessDetails:        CSMS.BusinessDetails,
                            OurCountryCode:            CSMS.PartyId.CountryCode,
                            OurPartyId:                CSMS.PartyId.PartyId,
                            OurRole:                   Role.CPO,

                            BaseAPI:                   BaseAPI,
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

        private void WireEvents()
        {

            var log = CSMS.Log;

            commonAPI.OnPostCredentialsResponse   += new V.OCPIResponseLogHandler((timestamp, api, request, response, cancellationToken) => {
                LogHandshake("registered with", request, response);
                return Task.CompletedTask;
            });

            commonAPI.OnPutCredentialsResponse    += new V.OCPIResponseLogHandler((timestamp, api, request, response, cancellationToken) => {
                LogHandshake("renewed its registration with", request, response);
                return Task.CompletedTask;
            });

            commonAPI.OnDeleteCredentialsResponse += new V.OCPIResponseLogHandler((timestamp, api, request, response, cancellationToken) => {
                LogHandshake("unregistered from", request, response);
                return Task.CompletedTask;
            });

            commonAPI.OnTokenStatusAdded    += tokenStatus => { LogToken(tokenStatus, "pushed");  return Task.CompletedTask; };
            commonAPI.OnTokenStatusChanged  += tokenStatus => { LogToken(tokenStatus, "changed"); return Task.CompletedTask; };


            void LogHandshake(String What, V.OCPIRequest Request, V.OCPIResponse Response)
            {

                var who     = Request.RemoteParty?.Id.ToString() ?? $"somebody at {Request.HTTPRequest.RemoteSocket}";
                var worked  = Response.StatusCode == StatusCode.Success;

                if (CSMS.OCPI.Logging?.Requests == false && worked)
                    return;

                log.Log(
                    worked ? LogLevel.Notice : LogLevel.Warning,
                    worked
                        ? $"The roaming partner {who} {What} this operator (OCPI 2.1.1)."
                        : $"The roaming partner {who} tried to {What.Split(' ')[0]} this operator and was answered {Response.StatusCode}: {Response.StatusMessage} (OCPI 2.1.1).",
                    "ocpi", "credentials", "partner"
                );

            }

            void LogToken(V.TokenStatus TokenStatus, String How)
            {

                if (CSMS.OCPI.Logging?.Requests == false)
                    return;

                log.Info(
                    $"The token '{TokenStatus.Token.Id}' of {TokenStatus.Token.CountryCode}-{TokenStatus.Token.PartyId} was {How} (OCPI 2.1.1).",
                    "ocpi", "tokens", "partner"
                );

            }

        }

        #endregion


        #region Roaming partners

        public override IEnumerable<RemotePartySummary> RemoteParties

            => commonAPI.RemoteParties.Select(party => Summarize(
                                                           party,
                                                           party.CountryCode,
                                                           party.PartyId,
                                                           party.Role,
                                                           party.BusinessDetails
                                                       ));


        public override async Task<String?> AddRemoteParty(RemotePartySpec Spec)
        {

            var businessDetails = new BusinessDetails(Spec.Name, Spec.Website);

            var result = Spec.CanRegister

                             ? await commonAPI.AddRemoteParty(
                                         CountryCode:                       Spec.CountryCode,
                                         PartyId:                           Spec.PartyId,
                                         Role:                              Spec.Role,
                                         BusinessDetails:                   businessDetails,
                                         LocalAccessToken:                  Spec.OurToken,
                                         RemoteVersionsURL:                 Spec.TheirVersionsURL!.Value,
                                         RemoteAccessToken:                 Spec.TheirToken!.Value,

                                         // OCPI 2.1.1 sends the token as it is;
                                         // the base64 encoding arrived with 2.2.
                                         RemoteAccessTokenBase64Encoding:   false,
                                         LocalAccessTokenBase64Encoding:    false,
                                         LocalAccessStatus:                 AccessStatus.ALLOWED,
                                         RemoteStatus:                      RemoteAccessStatus.ONLINE
                                     )

                             : await commonAPI.AddRemoteParty(
                                         CountryCode:                       Spec.CountryCode,
                                         PartyId:                           Spec.PartyId,
                                         Role:                              Spec.Role,
                                         BusinessDetails:                   businessDetails,
                                         LocalAccessToken:                  Spec.OurToken,
                                         LocalAccessTokenBase64Encoding:    false,
                                         LocalAccessStatus:                 AccessStatus.ALLOWED,
                                         Status:                            PartyStatus.ENABLED
                                     );

            return result.IsSuccess
                       ? null
                       : result.ErrorResponse ?? "The library declined to add the roaming partner and did not say why.";

        }


        public override Task<Boolean> RemoveRemoteParty(RemoteParty_Id Id)
            => commonAPI.RemoveRemoteParty(Id);


        public override async Task<OCPIOperationResult> Register(RemoteParty_Id Id)
        {

            if (!commonAPI.TryGetRemoteParty(Id, out var party))
                return OCPIOperationResult.Failed($"There is no roaming partner '{Id}' on OCPI 2.1.1.");

            var client = cpoAPI.GetEMSPClient(party, AllowCachedClients: false);

            if (client is null)
                return OCPIOperationResult.Failed($"'{Id}' has not handed out a token and a versions URL, so there is nowhere to send this operator's credentials.");

            var response = await client.Register();

            return DescribeRegistration(Id, response.StatusCode, response.StatusMessage, response.Data is not null);

        }

        #endregion

        #region What this operator publishes

        public override IEnumerable<JObject> Locations
            => commonAPI.GetLocations(CSMS.PartyId).Select(location => WithVersion(location.ToJSON()));

        public override IEnumerable<JObject> Tariffs
            => commonAPI.GetTariffs ().Select(tariff  => WithVersion(tariff. ToJSON()));

        public override IEnumerable<JObject> Sessions
            => commonAPI.GetSessions().Select(session => WithVersion(session.ToJSON()));

        public override IEnumerable<JObject> CDRs
            => commonAPI.GetCDRs    ().Select(cdr     => WithVersion(cdr.    ToJSON()));


        public override Boolean HasLocation(Location_Id Id)
            => commonAPI.GetLocations(CSMS.PartyId).Any(location => location.Id == Id);


        public override async Task<String?> AddLocation(LocationSpec Spec)
        {

            var result = await commonAPI.AddLocation(
                                   new V.Location(
                                       CSMS.PartyId.CountryCode,
                                       CSMS.PartyId.PartyId,
                                       Spec.Id,

                                       // A field 2.1.1 insists on and the
                                       // versions after it dropped. Nothing
                                       // here knows what kind of place a site
                                       // is, and saying so is better than
                                       // picking one.
                                       V.LocationType.UNKNOWN,

                                       Spec.Address,
                                       Spec.City,
                                       Spec.PostalCode,
                                       Spec.Country,
                                       Spec.Coordinates,
                                       Name:      Spec.Name,
                                       Operator:  CSMS.BusinessDetails,
                                       Timezone:  Spec.TimeZone,
                                       Publish:   Spec.Publish
                                   )
                               );

            return result.IsSuccess
                       ? null
                       : result.ErrorResponse ?? "The library declined to add the location and did not say why.";

        }


        public override async Task<Boolean> RemoveLocation(Location_Id Id)
        {

            var result = await commonAPI.RemoveLocation(Id);

            return result.IsSuccess;

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
