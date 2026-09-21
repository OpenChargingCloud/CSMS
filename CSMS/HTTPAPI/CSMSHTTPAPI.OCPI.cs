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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.CSMS.Web;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The part of the JSON API that is about OCPI: who this operator is and
    /// where it is, the roaming partners, the locations it publishes, and what
    /// travels between it and them.
    /// </summary>
    /// <remarks>
    /// Three groups of routes and three permissions. Reading is reading, and
    /// includes what the partners sent - a token is a record about somebody
    /// else's customer, but so is the log. Publishing a location is the
    /// operator's daily work. Adding a partner hands a foreign system the
    /// right to push into this operator and to start charging sessions at its
    /// stations, and is the highest of the three. See <see cref="Permissions"/>.
    ///
    /// A partner's tokens travel to the browser only for whoever may manage
    /// partners: the token this operator handed out is what somebody has to
    /// give the partner, so it has to be shown to them - and to nobody else,
    /// because it opens this operator.
    /// </remarks>
    public partial class CSMSHTTPAPI
    {

        #region (private) RegisterOCPIRoutes()

        /// <summary>
        /// Everything under /v1/configuration/ocpi and /v1/ocpi.
        /// </summary>
        private void RegisterOCPIRoutes()
        {

            AddHandler(HTTPPath.Root + "v1/configuration/ocpi",                    GetOCPIConfiguration,  HTTPMethod.GET);

            AddHandler(HTTPPath.Root + "v1/ocpi/partners",                         GetPartners,           HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/ocpi/partners",                         PostPartner,           HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/ocpi/partners/{version}/{id}/register", PostPartnerRegister,   HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/ocpi/partners/{version}/{id}",          DeletePartner,         HTTPMethod.DELETE);

            AddHandler(HTTPPath.Root + "v1/ocpi/locations",                        GetLocations,          HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/ocpi/locations",                        PostLocation,          HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/ocpi/locations/{version}/{id}",         DeleteLocation,        HTTPMethod.DELETE);

            AddHandler(HTTPPath.Root + "v1/ocpi/tokens",                           request => GetRoamingData(request, "tokens"),    HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/ocpi/tariffs",                          request => GetRoamingData(request, "tariffs"),   HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/ocpi/sessions",                         request => GetRoamingData(request, "sessions"),  HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/ocpi/cdrs",                             request => GetRoamingData(request, "cdrs"),      HTTPMethod.GET);

        }

        #endregion


        #region (private) GetOCPIConfiguration(Request)

        /// <summary>
        /// GET /api/v1/configuration/ocpi: who this operator is in OCPI, where
        /// its endpoints are, and how much has travelled.
        /// </summary>
        private Task<HTTPResponse> GetOCPIConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.OCPIConfigurationJSON())
                   );

        }

        #endregion

        #region (private) The roaming partners

        /// <summary>
        /// GET /api/v1/ocpi/partners: every roaming partner, over every
        /// version. The tokens travel along for whoever may manage partners.
        /// </summary>
        private Task<HTTPResponse> GetPartners(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ReadConfiguration, false, out var user, out var refused))
                return Task.FromResult(refused);

            var mayManage = PermissionsOf(user).HasFlag(Permissions.ManageRoamingPartners);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.RemotePartiesJSON(IncludeSecrets: mayManage))
                   );

        }

        /// <summary>
        /// POST /api/v1/ocpi/partners with {"version", "countryCode",
        /// "partyId", "role", "name", "website", "ourToken", "theirToken",
        /// "versionsURL"}: add a roaming partner.
        /// </summary>
        /// <remarks>
        /// An empty token of ours means "make one up", and it comes back in
        /// this response: somebody hands it to the partner, who registers with
        /// it. With the partner's own token and versions URL as well, this
        /// operator can start the peering itself - see
        /// <see cref="PostPartnerRegister"/>.
        /// </remarks>
        private async Task<HTTPResponse> PostPartner(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ManageRoamingPartners, true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var result = await CSMS.AddRemotePartyAsync(json);

            if (!result.Success)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, result.Message);

            Log.Info($"'{user.Id}' added the roaming partner '{result.Data?.Value<String>("id")}'.", "ocpi", "partner", "web");

            var response = new JObject(
                               new JProperty("message",   result.Message),
                               new JProperty("partners",  CSMS.RemotePartiesJSON(IncludeSecrets: true))
                           );

            if (result.Data is not null)
                foreach (var property in result.Data.Properties())
                    response[property.Name] = property.Value;

            return JSONResponse(Request, HTTPStatusCode.Created, response);

        }

        /// <summary>
        /// POST /api/v1/ocpi/partners/{version}/{id}/register: start the
        /// peering with a partner that handed out its token and versions URL.
        /// </summary>
        /// <remarks>
        /// A POST that sends traffic to a host somebody named, and every step
        /// of it is in the log - so the Logs page of anybody watching shows
        /// the handshake as it happens.
        /// </remarks>
        private async Task<HTTPResponse> PostPartnerRegister(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ManageRoamingPartners, true, out var user, out var refused))
                return refused;

            if (!TryGetVersionAndId(Request, out var version, out var id, out var badRequest))
                return badRequest;

            Log.Info($"'{user.Id}' asked this operator to register with the roaming partner '{id}' (OCPI {version}).", "ocpi", "credentials", "partner", "web");

            var result = await CSMS.RegisterRemotePartyAsync(version, id);

            return JSONResponse(
                       Request,
                       result.Success ? HTTPStatusCode.OK : HTTPStatusCode.BadGateway,
                       new JObject(
                           new JProperty("ok",        result.Success),
                           new JProperty("message",   result.Message),
                           new JProperty("partners",  CSMS.RemotePartiesJSON(IncludeSecrets: true))
                       )
                   );

        }

        /// <summary>
        /// DELETE /api/v1/ocpi/partners/{version}/{id}: forget a roaming
        /// partner.
        /// </summary>
        private async Task<HTTPResponse> DeletePartner(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ManageRoamingPartners, true, out var user, out var refused))
                return refused;

            if (!TryGetVersionAndId(Request, out var version, out var id, out var badRequest))
                return badRequest;

            var result = await CSMS.RemoveRemotePartyAsync(version, id);

            if (!result.Success)
                return ErrorJSON(Request, HTTPStatusCode.NotFound, result.Message);

            Log.Info($"'{user.Id}' removed the roaming partner '{id}' (OCPI {version}).", "ocpi", "partner", "web");

            return JSONResponse(Request, HTTPStatusCode.OK, CSMS.RemotePartiesJSON(IncludeSecrets: true));

        }

        #endregion

        #region (private) The locations this operator publishes

        /// <summary>
        /// GET /api/v1/ocpi/locations: every location this operator publishes.
        /// </summary>
        private Task<HTTPResponse> GetLocations(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.LocationsJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/ocpi/locations with {"version", "id", "name",
        /// "address", "city", "postalCode", "country", "latitude",
        /// "longitude", "timeZone", "publish"}: publish a location.
        /// </summary>
        private async Task<HTTPResponse> PostLocation(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ManageLocations, true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var result = await CSMS.AddLocationAsync(json);

            if (!result.Success)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, result.Message);

            Log.Info($"'{user.Id}' published the location '{result.Data?.Value<String>("id")}'.", "ocpi", "locations", "web");

            return JSONResponse(
                       Request,
                       HTTPStatusCode.Created,
                       new JObject(
                           new JProperty("message",    result.Message),
                           new JProperty("id",         result.Data?.Value<String>("id")),
                           new JProperty("version",    result.Data?.Value<String>("version")),
                           new JProperty("locations",  CSMS.LocationsJSON())
                       )
                   );

        }

        /// <summary>
        /// DELETE /api/v1/ocpi/locations/{version}/{id}: withdraw a location.
        /// </summary>
        private async Task<HTTPResponse> DeleteLocation(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permissions.ManageLocations, true, out var user, out var refused))
                return refused;

            if (!TryGetVersionAndId(Request, out var version, out var id, out var badRequest))
                return badRequest;

            var result = await CSMS.RemoveLocationAsync(version, id);

            if (!result.Success)
                return ErrorJSON(Request, HTTPStatusCode.NotFound, result.Message);

            Log.Info($"'{user.Id}' withdrew the location '{id}' (OCPI {version}).", "ocpi", "locations", "web");

            return JSONResponse(Request, HTTPStatusCode.OK, CSMS.LocationsJSON());

        }

        #endregion

        #region (private) GetRoamingData(Request, Kind)

        /// <summary>
        /// GET /api/v1/ocpi/{tokens|tariffs|sessions|cdrs}: what travels
        /// between this operator and its partners, over every version.
        /// </summary>
        private Task<HTTPResponse> GetRoamingData(HTTPRequest Request, String Kind)
        {

            if (!TryAuthorize(Request, Permissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.RoamingDataJSON(Kind))
                   );

        }

        #endregion


        #region (private static) TryGetVersionAndId(Request, out Version, out Id, out ErrorResponse)

        /// <summary>
        /// The version and the identification out of the path, or the 400
        /// that says one of them was missing.
        /// </summary>
        private static Boolean TryGetVersionAndId(HTTPRequest       Request,
                                                  out String        Version,
                                                  out String        Id,
                                                  out HTTPResponse  ErrorResponse)
        {

            var parameters = Request.ParsedURLParameters;

            Version        = parameters.Length > 0 ? parameters[0].Trim() : "";
            Id             = parameters.Length > 1 ? parameters[1].Trim() : "";
            ErrorResponse  = default!;

            if (Version.Length == 0 || Id.Length == 0)
            {
                ErrorResponse = ErrorJSON(Request, HTTPStatusCode.BadRequest, "An OCPI version and an identification are required.");
                return false;
            }

            return true;

        }

        #endregion

    }

}
