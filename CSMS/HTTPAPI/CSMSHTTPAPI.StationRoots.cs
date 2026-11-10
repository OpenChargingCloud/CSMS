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

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The part of the JSON API that installs root certificates on the
    /// charging stations, and says what they have.
    /// </summary>
    /// <remarks>
    /// | | |
    /// |---|---|
    /// | <c>GET v1/configuration/station-roots</c> | the roots, the stations connected, and the latest changes on the stations |
    /// | <c>POST v1/configuration/station-roots</c> | <c>{ pem, certificateType, everywhere }</c>: a root added |
    /// | <c>POST v1/configuration/station-roots/from-pki</c> | the roots the EST servers of the PKI name, added |
    /// | <c>PUT v1/configuration/station-roots/{type}/{id}</c> | <c>{ everywhere }</c>: whether every station is to have it |
    /// | <c>DELETE v1/configuration/station-roots/{type}/{id}</c> | no longer installed - it stays where it is |
    /// | <c>POST v1/configuration/station-roots/{type}/{id}/install</c> | <c>{ station }</c>: installed on that station, or on every one connected where none is named |
    /// | <c>GET v1/configuration/station-roots/stations/{station}</c> | what the station has, GetInstalledCertificateIds |
    /// | <c>POST v1/configuration/station-roots/stations/{station}/delete</c> | <c>{ certificateType, hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }</c>: deleted from the station |
    /// <para>
    /// Reading at the stations' permission - asking a station what it has
    /// changes nothing on it - and changing at the certificates': what a
    /// station trusts is whom it lets sign it, and whom it signs in to.
    /// </para>
    /// </remarks>
    public partial class CSMSHTTPAPI
    {

        #region (private) RegisterStationRootRoutes()

        private void RegisterStationRootRoutes()
        {

            var root = HTTPPath.Root + "v1/configuration/station-roots";

            AddHandler(root,                                     GetStationRoots,           HTTPMethod.GET);
            AddHandler(root,                                     PostStationRoot,           HTTPMethod.POST);
            AddHandler(root + "/from-pki",                       PostStationRootsFromPKI,   HTTPMethod.POST);
            AddHandler(root + "/{type}/{id}",                    PutStationRoot,            HTTPMethod.PUT);
            AddHandler(root + "/{type}/{id}",                    DeleteStationRoot,         HTTPMethod.DELETE);
            AddHandler(root + "/{type}/{id}/install",            PostStationRootInstall,    HTTPMethod.POST);
            AddHandler(root + "/stations/{station}",             GetStationCertificates,    HTTPMethod.GET);
            AddHandler(root + "/stations/{station}/delete",      PostStationCertificateDelete, HTTPMethod.POST);

        }

        #endregion


        #region (private) GetStationRoots(Request)

        private Task<HTTPResponse> GetStationRoots(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(CSMSAccess.Stations), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.StationRootsJSON()));

        }

        #endregion

        #region (private) PostStationRoot(Request) / PostStationRootsFromPKI(Request)

        /// <summary>
        /// POST .../station-roots: answered as GET is; 400 with why where it
        /// is no root, or one there is already.
        /// </summary>
        private Task<HTTPResponse> PostStationRoot(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var pem        = json["pem"]?.            Type == JTokenType.String  ? json["pem"]!.            Value<String>()!        : null;
            var type       = json["certificateType"]?.Type == JTokenType.String  ? json["certificateType"]!.Value<String>()!.Trim() : null;
            var everywhere = json["everywhere"]?.     Type == JTokenType.Boolean && json["everywhere"]!.Value<Boolean>();

            if (String.IsNullOrWhiteSpace(pem) || String.IsNullOrEmpty(type))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "Say which certificate, and what it is to the stations: { \"pem\", \"certificateType\", \"everywhere\" }."));

            if (!CSMS.StationRoots.TryAdd(pem, type, everywhere, DateTimeOffset.UtcNow, out var root, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            Log.Notice($"'{user.Id}' added the {type} '{root.Subject}'{(everywhere ? ", for every station" : "")}.", "ocpp", "certificate", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, CSMS.StationRootsJSON()));

        }

        /// <summary>
        /// POST .../station-roots/from-pki: answered as GET is, with what was
        /// added and what could not be asked.
        /// </summary>
        private async Task<HTTPResponse> PostStationRootsFromPKI(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            if (!CSMS.CertificateSigning.Signs)
                return ErrorJSON(Request, HTTPStatusCode.Conflict, "This CSMS knows of no PKI: it sends CSRs to no EST server.");

            var (added, problems) = await CSMS.RootsFromPKI();

            Log.Info($"'{user.Id}' took the roots of the PKI: {added.Count} added.", "ocpp", "certificate", "web");

            var json = CSMS.StationRootsJSON();
            json.Add("added",     new JArray(added.Select(root => root.ToJSON())));
            json.Add("problems",  new JArray(problems));

            return JSONResponse(Request, HTTPStatusCode.OK, json);

        }

        #endregion

        #region (private) PutStationRoot(Request) / DeleteStationRoot(Request)

        private Task<HTTPResponse> PutStationRoot(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetRoot(Request, out var root, out var notFound))
                return Task.FromResult(notFound);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (json["everywhere"]?.Type != JTokenType.Boolean)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "Say whether every station is to have it: { \"everywhere\": true }."));

            var everywhere = json["everywhere"]!.Value<Boolean>();

            CSMS.StationRoots.TrySetEverywhere(root.Id, root.CertificateType, everywhere);

            Log.Notice($"'{user.Id}' said the {root.CertificateType} '{root.Subject}' is {(everywhere ? "for every station" : "installed by hand")}.", "ocpp", "certificate", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.StationRootsJSON()));

        }

        private Task<HTTPResponse> DeleteStationRoot(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetRoot(Request, out var root, out var notFound))
                return Task.FromResult(notFound);

            CSMS.StationRoots.TryRemove(root.Id, root.CertificateType);

            Log.Notice($"'{user.Id}' removed the {root.CertificateType} '{root.Subject}' from the roots for the stations.", "ocpp", "certificate", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.StationRootsJSON()));

        }

        #endregion

        #region (private) PostStationRootInstall(Request)

        /// <summary>
        /// POST .../station-roots/{type}/{id}/install: what each station
        /// answered - 200 whatever it answered, 409 where the one named is not
        /// connected.
        /// </summary>
        private async Task<HTTPResponse> PostStationRootInstall(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            if (!TryGetRoot(Request, out var root, out var notFound))
                return notFound;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var station  = json["station"]?.Type == JTokenType.String ? json["station"]!.Value<String>()!.Trim() : null;

            if (station is { Length: 0 or > 255 })
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "Say which station, or none for every one connected: { \"station\" }.");

            var stations = station is not null ? [ station ] : CSMS.ConnectedStations;

            if (stations.Count == 0)
                return ErrorJSON(Request, HTTPStatusCode.Conflict, "No charging station is connected.");

            var results  = new JArray();

            foreach (var one in stations)
            {

                var answer = await CSMS.InstallRoot(one, root);

                if (station is not null && !answer.Asked)
                    return ErrorJSON(Request, HTTPStatusCode.Conflict, answer.Detail ?? answer.Answer);

                results.Add(new JObject(
                                new JProperty("station",  one),
                                new JProperty("answer",   answer.Answer),
                                new JProperty("detail",   answer.Detail)
                            ));

            }

            Log.Info($"'{user.Id}' installed the {root.CertificateType} '{root.Subject}' on {(station is not null ? $"'{station}'" : $"{stations.Count} station(s)")}.", "ocpp", "certificate", "web");

            var result = CSMS.StationRootsJSON();
            result.Add("results", results);

            return JSONResponse(Request, HTTPStatusCode.OK, result);

        }

        #endregion

        #region (private) GetStationCertificates(Request) / PostStationCertificateDelete(Request)

        /// <summary>
        /// GET .../station-roots/stations/{station}: what it has; 409 where it
        /// is not connected, 502 where it did not answer as it should.
        /// </summary>
        private async Task<HTTPResponse> GetStationCertificates(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(CSMSAccess.Stations), false, out _, out var refused))
                return refused;

            var station = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            if (station.Length is 0 or > 255)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "Say which station.");

            var answer  = await CSMS.InstalledOn(station);

            if (!answer.Asked)
                return ErrorJSON(Request, HTTPStatusCode.Conflict, answer.Detail ?? answer.Answer);

            if (answer.Installed is null)
                return ErrorJSON(Request, HTTPStatusCode.BadGateway, answer.Detail ?? answer.Answer);

            return JSONResponse(Request,
                                HTTPStatusCode.OK,
                                new JObject(
                                    new JProperty("station",    station),
                                    new JProperty("installed",  new JArray(answer.Installed.Select(one => one.ToJSON())))
                                ));

        }

        /// <summary>
        /// POST .../station-roots/stations/{station}/delete: what the station
        /// answered; 409 where it is not connected.
        /// </summary>
        private async Task<HTTPResponse> PostStationCertificateDelete(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var station = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            String? Text(String Name)
                => json[Name]?.Type == JTokenType.String ? json[Name]!.Value<String>()!.Trim() : null;

            var type        = Text("certificateType");
            var algorithm   = Text("hashAlgorithm");
            var nameHash    = Text("issuerNameHash");
            var keyHash     = Text("issuerKeyHash");
            var serial      = Text("serialNumber");

            if (station.Length is 0 or > 255 ||
                String.IsNullOrEmpty(type) || algorithm is not ("SHA256" or "SHA384" or "SHA512") ||
                String.IsNullOrEmpty(nameHash) || nameHash.Length > 128 || !nameHash.All(Uri.IsHexDigit) ||
                String.IsNullOrEmpty(keyHash)  || keyHash. Length > 128 || !keyHash. All(Uri.IsHexDigit) ||
                String.IsNullOrEmpty(serial)   || serial.  Length > 40  || !serial.  All(Uri.IsHexDigit))
            {
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 "Say which certificate, as the station names it: { \"certificateType\", \"hashAlgorithm\", \"issuerNameHash\", \"issuerKeyHash\", \"serialNumber\" }.");
            }

            var answer = await CSMS.DeleteFrom(station, type, algorithm, nameHash, keyHash, serial);

            if (!answer.Asked)
                return ErrorJSON(Request, HTTPStatusCode.Conflict, answer.Detail ?? answer.Answer);

            Log.Info($"'{user.Id}' deleted the {type} {serial} from '{station}': {answer.Answer}.", "ocpp", "certificate", "web");

            return JSONResponse(Request,
                                HTTPStatusCode.OK,
                                new JObject(
                                    new JProperty("answer",  answer.Answer),
                                    new JProperty("detail",  answer.Detail)
                                ));

        }

        #endregion


        #region (private) TryGetRoot(Request, out Root, out NotFound)

        private Boolean TryGetRoot(HTTPRequest Request, out StationRoot Root, out HTTPResponse NotFound)
        {

            var type  = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";
            var id    = Request.ParsedURLParameters.ElementAtOrDefault(1)?.Trim() ?? "";

            Root      = default!;
            NotFound  = default!;

            if (CSMS.StationRoots.Get(id, type) is StationRoot root)
            {
                Root = root;
                return true;
            }

            NotFound = ErrorJSON(Request, HTTPStatusCode.NotFound, $"No {type} '{id}' is kept for the stations.");
            return false;

        }

        #endregion

    }

}
