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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The part of the JSON API that is about the certificate store of the
    /// node below: what it holds, putting certificates in, switching them on
    /// and off, saying what they are for, and taking them out again.
    /// </summary>
    /// <remarks>
    /// Not the charging station server's own keys and the chains it accepts
    /// charging stations by, which are stores of their own with routes of
    /// their own - see CSMSHTTPAPI.OCPPServer.cs. Both are the one resource
    /// "certificates", because both are decisions about trust.
    /// </remarks>
    public partial class CSMSHTTPAPI
    {

        #region (private) RegisterCertificateRoutes()

        /// <summary>
        /// Everything under /v1/certificates.
        /// </summary>
        private void RegisterCertificateRoutes()
        {

            AddHandler(HTTPPath.Root + "v1/certificates",         GetStoreCertificates,        HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates",         PostStoreCertificate,        HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/reload",  PostStoreCertificateReload,  HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/{id}",    GetStoreCertificate,         HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/{id}",    PatchStoreCertificate,       HTTPMethod.PATCH);
            AddHandler(HTTPPath.Root + "v1/certificates/{id}",    DeleteStoreCertificate,      HTTPMethod.DELETE);

        }

        #endregion

        #region (private) GetStoreCertificates(Request) / PostStoreCertificate(Request)

        /// <summary>
        /// GET /api/v1/certificates: everything in this CSMS's store.
        /// </summary>
        /// <remarks>
        /// Grouped by kind rather than returned as one list, because the page
        /// that reads it shows the roots this CSMS believes and what it
        /// presents as two different things - and because a flat list would
        /// put a TLS root next to a TLS identity with one word between them.
        ///
        /// At the reading permission: what certificates a CSMS holds is not
        /// a secret from anybody who may look at it at all, and the private
        /// keys are not in the answer. Changing any of it needs
        /// "certificates:edit", which only the administrators have unless the
        /// configuration file says otherwise.
        /// </remarks>
        private Task<HTTPResponse> GetStoreCertificates(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.CertificatesJSON())
                   );

        }

        /// <summary>
        /// POST /api/v1/certificates with {"kind", "content", "password", "label",
        /// "usages"}: put a certificate into the store.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The file arrives as base64 in <c>content</c>, which is what an
        /// upload from the browser turns into. The password is what opens it if
        /// it is a protected PKCS#12, is used once here, and is not kept: the
        /// store writes what it holds without one.
        /// </para>
        /// <para>
        /// Answered with 200 rather than 201 when the certificate was already
        /// there. Importing the same file twice is the same entry - the id is
        /// its fingerprint - so the second import created nothing.
        /// </para>
        /// <para>
        /// <c>usages</c> says what a TLS root or a server certificate is for -
        /// ["dns", "nts"] - and is left out, or null, for every use.
        /// </para>
        /// </remarks>
        private Task<HTTPResponse> PostStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!CertificateKindExtensions.TryParseKind(json.Value<String>("kind"), out var kind))
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     "'kind' has to be one of " +
                                     String.Join(", ", CertificateKindExtensions.All.Select(one => one.AsText())) + ".")
                       );

            var content = json.Value<String>("content")?.Trim();

            if (content is null or { Length: 0 })
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                     "'content' has to be the certificate file, base64-encoded.")
                       );

            Byte[] bytes;

            try
            {
                bytes = Convert.FromBase64String(content);
            }
            catch (FormatException)
            {
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest, "'content' is not valid base64.")
                       );
            }

            if (!TryReadUsages(json, out var usages, out var usagesError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError));

            var existed = CSMS.Certificates.Entries.Count;

            if (!CSMS.Certificates.Import(bytes,
                                             kind,
                                             json.Value<String>("password"),
                                             json.Value<String>("label"),
                                             usages,
                                             out var entry,
                                             out var error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            return Task.FromResult(
                       JSONResponse(
                           Request,
                           CSMS.Certificates.Entries.Count > existed
                               ? HTTPStatusCode.Created
                               : HTTPStatusCode.OK,
                           entry.ToJSON(WithDiagnostics: true)
                       )
                   );

        }

        #endregion

        #region (private) GetStoreCertificate(Request) / PatchStoreCertificate(Request) / DeleteStoreCertificate(Request)

        /// <summary>
        /// GET /api/v1/certificates/{id}: one certificate.
        /// </summary>
        private Task<HTTPResponse> GetStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            var entry = CSMS.Certificates.Get(HandleOf(Request));

            return Task.FromResult(
                       entry is null
                           ? ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no such certificate in this store.")
                           : JSONResponse(Request, HTTPStatusCode.OK, entry.ToJSON(WithDiagnostics: true))
                   );

        }

        /// <summary>
        /// PATCH /api/v1/certificates/{id} with {"active"}, {"label"} and/or
        /// {"usages"}: switch a certificate on or off, rename it, or say what
        /// it is for.
        /// </summary>
        /// <remarks>
        /// Three things in one request because they are the only three things
        /// about a stored certificate that can be changed at all - everything
        /// else about it is read out of the file and is not somebody's to edit.
        /// "usages" set to null is every use again; left out, it is left alone.
        /// </remarks>
        private Task<HTTPResponse> PatchStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var handle = HandleOf(Request);

            if (CSMS.Certificates.Get(handle) is null)
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no such certificate in this store.")
                       );

            if (json.TryGetValue("label", out var label) && label.Type != JTokenType.Undefined)
            {
                if (!CSMS.Certificates.Relabel(handle, label.Value<String>(), out _, out var relabelError))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, relabelError));
            }

            if (json.TryGetValue("active", out var active))
            {

                if (active.Type != JTokenType.Boolean)
                    return Task.FromResult(
                               ErrorJSON(Request, HTTPStatusCode.BadRequest, "'active' has to be true or false.")
                           );

                if (!CSMS.Certificates.SetActive(handle, active.Value<Boolean>(), out _, out var activeError))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, activeError));

            }

            // Present, even as null, is something to set: null is every use.
            if (json.ContainsKey("usages"))
            {

                if (!TryReadUsages(json, out var usages, out var usagesError))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError));

                if (!CSMS.Certificates.SetUsages(handle, usages, out _, out var usagesRefused))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesRefused));

            }

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                                    CSMS.Certificates.Get(handle)!.ToJSON(WithDiagnostics: true))
                   );

        }

        /// <summary>
        /// DELETE /api/v1/certificates/{id}: take a certificate out of the
        /// store and delete its file.
        /// </summary>
        /// <remarks>
        /// Switching it off is what somebody taking a certificate out of
        /// service usually meant, and keeps it at hand for the day it is
        /// wanted back; this is for a certificate nobody will want again.
        /// </remarks>
        private Task<HTTPResponse> DeleteStoreCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out _, out var refused))
                return Task.FromResult(refused);

            var handle = HandleOf(Request);

            if (!CSMS.Certificates.Remove(handle, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, error));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.CertificatesJSON())
                   );

        }

        #endregion

        #region (private) PostStoreCertificateReload(Request)

        /// <summary>
        /// POST /api/v1/certificates/reload: read the store directory again.
        /// </summary>
        /// <remarks>
        /// What the store does at every start, on demand: certificates somebody
        /// copied into the directory are adopted, and entries whose files are
        /// gone are dropped. It exists because putting a file in a directory is
        /// a perfectly good way to install a certificate on a machine somebody
        /// already has a shell on, and having to restart the CSMS to be
        /// noticed would make it a worse one.
        /// </remarks>
        private Task<HTTPResponse> PostStoreCertificateReload(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out _, out var refused))
                return Task.FromResult(refused);

            CSMS.Certificates.Reload();

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, CSMS.CertificatesJSON())
                   );

        }

        #endregion

        #region (private static) TryReadUsages(JSON, out Usages, out Error)

        /// <summary>
        /// The "usages" of a request: absent or null for every use, or a list
        /// of usages - or why not.
        /// </summary>
        /// <remarks>
        /// Whether each of them is a usage the store knows is the store's to
        /// say, and it says so in a sentence that names the ones it knows.
        /// </remarks>
        private static Boolean TryReadUsages(JObject                           JSON,
                                             out IReadOnlyList<String>?        Usages,
                                             [NotNullWhen(false)] out String?  Error)
        {

            Usages  = null;
            Error   = null;

            if (!JSON.TryGetValue("usages", out var token) || token.Type == JTokenType.Null)
                return true;

            if (token is not JArray array || array.Any(usage => usage.Type != JTokenType.String))
            {
                Error = "'usages' has to be a list of usages, such as [\"dns\", \"nts\"], or null for every use.";
                return false;
            }

            Usages = [.. array.Select(usage => usage.Value<String>()!)];
            return true;

        }

        #endregion

        #region (private static) HandleOf(Request)

        /// <summary>
        /// The certificate handle out of the request's path.
        /// </summary>
        private static String HandleOf(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? Request.ParsedURLParameters[0].Trim()
                   : "";

        #endregion

    }

}
