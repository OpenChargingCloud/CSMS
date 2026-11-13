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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The part of the JSON API that hands the charging stations behind the local controllers their key pins,
    /// rolls a controller's key over, and makes the key the pin sets are signed with (white paper "Key Pins and
    /// TLS 1.3 Raw Public Keys for Local Controllers", sections 5.5 to 5.7).
    /// </summary>
    /// <remarks>
    /// | | |
    /// |---|---|
    /// | <c>GET v1/key-pins</c> | the signing key's public part, and every local controller with the key pins last read of it and the stations behind it |
    /// | <c>GET v1/key-pins/local-controllers/{controller}</c> | one of them; 404 where it is not known |
    /// | <c>POST v1/key-pins/local-controllers/{controller}/rollover</c> | <c>{ graceSeconds }</c>, optional: rolled over to its announced next key, answered when it is done - 200 with what came of it, 409 where it was refused or stopped |
    /// | <c>POST v1/key-pins/local-controllers/{controller}/uplink</c> | <c>{ pins }</c>, optional: a signed pin set for the controller's own line to this CSMS - this CSMS's own key pins, or the given ones: 200 or 409 as above |
    /// | <c>POST v1/key-pins/confirm/{station or controller}</c> | the controller's key pins as it reports them now, handed to the station or to every station behind it: 200 or 409 as above |
    /// | <c>DELETE v1/key-pins/stations/{station}</c> | a station that moved: the controller it was behind forgotten, and the route through it - 200 with the controller; 404 where it was known behind none |
    /// | <c>GET v1/key-pins/signer</c> | the public key of the signing key, as a station's pin set signers take it |
    /// | <c>POST v1/key-pins/signer</c> | the signing key made: 201 with its public key; 409 where there is one |
    /// <para>
    /// Reading at the stations' permission; everything that changes whom a station believes - a pin set, a
    /// switch, the signing key, where a station's pin sets go - at the certificates', which only the
    /// administrators have.
    /// </para>
    /// </remarks>
    public partial class CSMSHTTPAPI
    {

        #region (private) RegisterKeyPinRoutes()

        private void RegisterKeyPinRoutes()
        {

            var root = HTTPPath.Root + "v1/key-pins";

            AddHandler(root,                                                GetKeyPins,              HTTPMethod.GET);
            AddHandler(root + "/local-controllers/{localController}",          GetLocalControllerPins,  HTTPMethod.GET);
            AddHandler(root + "/local-controllers/{localController}/rollover", PostRollover,            HTTPMethod.POST);
            AddHandler(root + "/local-controllers/{localController}/uplink",   PostUplink,              HTTPMethod.POST);
            AddHandler(root + "/confirm/{node}",                            PostConfirm,             HTTPMethod.POST);
            AddHandler(root + "/stations/{station}",                        DeleteStationBehind,     HTTPMethod.DELETE);
            AddHandler(root + "/signer",                                    GetPinSetSigner,         HTTPMethod.GET);
            AddHandler(root + "/signer",                                    PostPinSetSigner,        HTTPMethod.POST);

        }

        #endregion

        #region (private) GetKeyPins(Request) / GetLocalControllerPins(Request)

        /// <summary>
        /// GET /api/v1/key-pins.
        /// </summary>
        private Task<HTTPResponse> GetKeyPins(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(CSMSAccess.Stations), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.KeyPinsJSON()));

        }

        /// <summary>
        /// GET /api/v1/key-pins/local-controllers/{localController}.
        /// </summary>
        private Task<HTTPResponse> GetLocalControllerPins(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(CSMSAccess.Stations), false, out _, out var refused))
                return Task.FromResult(refused);

            var controller = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            return Task.FromResult(
                       CSMS.KeyPinsJSON(controller) is JObject json
                           ? JSONResponse(Request, HTTPStatusCode.OK, json)
                           : ErrorJSON   (Request, HTTPStatusCode.NotFound, $"'{controller}' is no local controller this CSMS knows charging stations behind.")
                   );

        }

        #endregion

        #region (private) PostRollover(Request)

        /// <summary>
        /// POST /api/v1/key-pins/local-controllers/{localController}/rollover, answered once it is done.
        /// </summary>
        private async Task<HTTPResponse> PostRollover(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            var controller = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            TimeSpan? grace = null;

            if (Request.HTTPBody is { Length: > 0 })
            {

                if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                    return errorResponse;

                if (json["graceSeconds"] is JToken token && token.Type != JTokenType.Null)
                {

                    if (token.Type != JTokenType.Integer || token.Value<Int64>() < 0 || token.Value<Int64>() > (Int64) CSMS.MaxRolloverGrace.TotalSeconds)
                        return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                         $"'graceSeconds' is a whole number of seconds from 0 to {(Int64) CSMS.MaxRolloverGrace.TotalSeconds}.");

                    grace = TimeSpan.FromSeconds(token.Value<Int64>());

                }

            }

            Log.Notice($"'{user.Id}' rolls the local controller '{controller}' over to its next key.", "ocpp", "keypins", "security", "web");

            var run = await CSMS.RolloverAsync(controller, grace);

            return JSONResponse(Request, run.Done ? HTTPStatusCode.OK : HTTPStatusCode.Conflict, run.ToJSON());

        }

        #endregion

        #region (private) PostUplink(Request)

        /// <summary>
        /// POST /api/v1/key-pins/local-controllers/{localController}/uplink, answered once it is done.
        /// </summary>
        private async Task<HTTPResponse> PostUplink(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            var controller = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            List<KeyPin>? pins = null;

            if (Request.HTTPBody is { Length: > 0 })
            {

                if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                    return errorResponse;

                if (json["pins"] is JToken token && token.Type != JTokenType.Null)
                {

                    if (token is not JArray array || array.Count == 0 || array.Count > 8 || array.Any(pin => pin.Type != JTokenType.String))
                        return ErrorJSON(Request, HTTPStatusCode.BadRequest, "'pins' is a list of 1 to 8 key pins, each as 64 hexadecimal digits.");

                    pins = [];

                    foreach (var text in array.Select(pin => pin.Value<String>()))
                    {

                        if (!KeyPin.TryParse(text, out var pin))
                            return ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'{text}' is no key pin: the SHA-256 of a public key, as 64 hexadecimal digits.");

                        pins.Add(pin);

                    }

                }

            }

            Log.Notice($"'{user.Id}' hands the local controller '{controller}' " +
                       (pins is null ? "this CSMS's key pins" : $"the key pins {String.Join(", ", pins.Select(pin => pin.ToHex()))}") +
                       " for its own line to this CSMS.", "ocpp", "keypins", "security", "web");

            var run = await CSMS.ConfirmUplinkAsync(controller, pins);

            return JSONResponse(Request, run.Done ? HTTPStatusCode.OK : HTTPStatusCode.Conflict, run.ToJSON());

        }

        #endregion

        #region (private) PostConfirm(Request)

        /// <summary>
        /// POST /api/v1/key-pins/confirm/{node}, answered once it is done.
        /// </summary>
        private async Task<HTTPResponse> PostConfirm(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return refused;

            var node = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            Log.Notice($"'{user.Id}' hands '{node}' the key pins of its local controller.", "ocpp", "keypins", "security", "web");

            var run = await CSMS.ConfirmAsync(node);

            return JSONResponse(Request, run.Done ? HTTPStatusCode.OK : HTTPStatusCode.Conflict, run.ToJSON());

        }

        #endregion

        #region (private) DeleteStationBehind(Request)

        /// <summary>
        /// DELETE /api/v1/key-pins/stations/{station}: 200 with the controller it was behind; 404 where none.
        /// </summary>
        private Task<HTTPResponse> DeleteStationBehind(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            var station = Request.ParsedURLParameters.ElementAtOrDefault(0)?.Trim() ?? "";

            if (CSMS.ForgetWhereAStationIs(station) is not String controller)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"'{station}' is not known behind a local controller."));

            Log.Notice($"'{user.Id}' made this CSMS forget that the charging station '{station}' is behind '{controller}'.",
                       "ocpp", "keypins", "security", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                                                                                new JProperty("station",          station),
                                                                                new JProperty("localController",  controller)
                                                                            )));

        }

        #endregion

        #region (private) GetPinSetSigner(Request) / PostPinSetSigner(Request)

        /// <summary>
        /// GET /api/v1/key-pins/signer.
        /// </summary>
        private Task<HTTPResponse> GetPinSetSigner(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(CSMSAccess.Stations), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CSMS.PinSetSigner.ToJSON()));

        }

        /// <summary>
        /// POST /api/v1/key-pins/signer: 201 with the public key; 409 where there is a key already.
        /// </summary>
        private Task<HTTPResponse> PostPinSetSigner(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            // One there is, or one in a file that could not be read, is never
            // made anew; anything else that stops it is this CSMS's.
            var there = CSMS.PinSetSigner.Exists || File.Exists(CSMS.PinSetSigner.Path);

            if (!CSMS.PinSetSigner.TryCreate(user.Id.ToString(), out var publicKey, out var error))
                return Task.FromResult(ErrorJSON(Request, there ? HTTPStatusCode.Conflict : HTTPStatusCode.InternalServerError, error));

            Log.Notice($"'{user.Id}' made the signing key for pin sets; its public key is {publicKey}.", "ocpp", "keypins", "security", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, CSMS.PinSetSigner.ToJSON()));

        }

        #endregion

    }

}
