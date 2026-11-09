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

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The part of the JSON API that says where the CSRs of the charging
    /// stations go - the EST server of a PKI - and what became of them.
    /// </summary>
    /// <remarks>
    /// | | |
    /// |---|---|
    /// | <c>GET v1/configuration/certificate-signing</c> | where each kind of certificate is signed, whether there is an API key, and the latest requests |
    /// | <c>PUT v1/configuration/certificate-signing</c> | <c>{ chargingStationCertificate, v2gCertificate, apiKey, renewDaysBefore }</c>: what is named is changed, null removes it, and what is not named stays |
    /// | <c>POST v1/configuration/certificate-signing/renew</c> | <c>{ station, certificateType }</c>: the station is asked for a new certificate of that kind now, and what it answered is said |
    /// | <c>DELETE v1/configuration/certificate-signing/certificates/{station}/{certificateType}</c> | the certificate is forgotten, and not renewed any more - until the station signs in with it, or is signed a new one |
    /// <para>
    /// Reading at the stations' permission; changing at the certificates',
    /// which only the administrators have: where the CSRs go is who signs the
    /// certificates the stations sign in with. Asking a station to renew is
    /// at the certificates' permission as well: it has a certificate signed.
    /// </para>
    /// </remarks>
    public partial class CSMSHTTPAPI
    {

        #region (private) RegisterCertificateSigningRoutes()

        private void RegisterCertificateSigningRoutes()
        {

            var root = HTTPPath.Root + "v1/configuration/certificate-signing";

            AddHandler(root, GetCertificateSigning, HTTPMethod.GET);
            AddHandler(root, PutCertificateSigning, HTTPMethod.PUT);

            AddHandler(root + "/renew", PostCertificateRenewal, HTTPMethod.POST);

            AddHandler(root + "/certificates/{station}/{certificateType}", DeleteStationCertificate, HTTPMethod.DELETE);

        }

        #endregion

        #region (private) GetCertificateSigning(Request) / PutCertificateSigning(Request)

        /// <summary>
        /// GET /api/v1/configuration/certificate-signing.
        /// </summary>
        private Task<HTTPResponse> GetCertificateSigning(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(CSMSAccess.Stations), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.CertificateSigningJSON()));

        }

        /// <summary>
        /// PUT /api/v1/configuration/certificate-signing; answered as GET is.
        /// </summary>
        private Task<HTTPResponse> PutCertificateSigning(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!CSMS.TryUpdateCertificateSigning(json, out var error, out var notSaved))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));

            Log.Info($"'{user.Id}' changed where the certificates of the charging stations are signed: {CSMS.CertificateSigning}.", "ocpp", "certificate", "config", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.CertificateSigningJSON()));

        }

        #endregion

        #region (private) PostCertificateRenewal(Request)

        /// <summary>
        /// POST /api/v1/configuration/certificate-signing/renew: 200 with what
        /// the station answered, whatever it answered; 409 where it is not
        /// connected; 400 where the kind of certificate is one this CSMS does
        /// not sign.
        /// </summary>
        private async Task<HTTPResponse> PostCertificateRenewal(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var station = json["station"]?.        Type == JTokenType.String ? json["station"]!.        Value<String>()!.Trim() : null;
            var type    = json["certificateType"]?.Type == JTokenType.String ? json["certificateType"]!.Value<String>()!.Trim() : null;

            if (String.IsNullOrEmpty(station) || station.Length > 255 || String.IsNullOrEmpty(type))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "Say which station, and which certificate: { \"station\", \"certificateType\" }.");

            var renewal = await CSMS.AskToRenew(station, type);

            if (!renewal.Asked)
                return ErrorJSON(Request,
                                 renewal.Answer == CSMS.NotConnected ? HTTPStatusCode.Conflict : HTTPStatusCode.BadRequest,
                                 renewal.Detail ?? renewal.Answer);

            Log.Info($"'{user.Id}' asked '{station}' for a new {type}: {renewal.Answer}.", "ocpp", "certificate", "web");

            return JSONResponse(Request,
                                HTTPStatusCode.OK,
                                new JObject(
                                    new JProperty("answer",  renewal.Answer),
                                    new JProperty("detail",  renewal.Detail)
                                ));

        }

        #endregion

        #region (private) DeleteStationCertificate(Request)

        /// <summary>
        /// DELETE /api/v1/configuration/certificate-signing/certificates/{station}/{certificateType}:
        /// answered as GET is; 404 where no such certificate is known.
        /// </summary>
        private Task<HTTPResponse> DeleteStationCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            var station = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";
            var type    = Request.ParsedURLParameters.ElementAtOrDefault(1)?.Trim() ?? "";

            if (station.Length == 0 || type.Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "Say which station, and which certificate."));

            if (CSMS.StationCertificates.Forget(station, type) == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"No {type} of '{station}' is known."));

            Log.Info($"'{user.Id}' had the {type} of '{station}' forgotten: it is not renewed any more.", "ocpp", "certificate", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.CertificateSigningJSON()));

        }

        #endregion

    }

}
