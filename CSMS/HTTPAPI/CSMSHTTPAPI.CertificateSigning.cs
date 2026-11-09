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
    /// | <c>PUT v1/configuration/certificate-signing</c> | <c>{ chargingStationCertificate, v2gCertificate, apiKey }</c>: what is named is changed, null removes it, and what is not named stays |
    /// <para>
    /// Reading at the stations' permission; changing at the certificates',
    /// which only the administrators have: where the CSRs go is who signs the
    /// certificates the stations sign in with.
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

    }

}
