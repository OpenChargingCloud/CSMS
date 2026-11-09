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

using System.Net.Http.Headers;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.OCPPv2_1;
using cloud.charging.open.protocols.OCPPv2_1.CS;
using cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// What became of one GetCertificateStatus request of a charging station.
    /// </summary>
    /// <param name="At">When the station asked.</param>
    /// <param name="Station">The charging station, by its identity.</param>
    /// <param name="SerialNumber">The serial number of the certificate it asked about, in hexadecimal.</param>
    /// <param name="Responder">The OCSP responder it named.</param>
    /// <param name="Outcome">"good", "revoked" or "unknown", as the responder said; "answered", where the responder answered and not of that certificate; "refused", where the request was not sent on; "failed", where the responder did not answer, or not successfully.</param>
    /// <param name="Detail">Why, in a sentence, where it was not answered; null otherwise.</param>
    /// <param name="NextUpdate">Until when the answer holds, where the responder says so.</param>
    public sealed record CertificateStatusEntry(DateTimeOffset   At,
                                                String           Station,
                                                String           SerialNumber,
                                                String           Responder,
                                                String           Outcome,
                                                String?          Detail       = null,
                                                DateTimeOffset?  NextUpdate   = null)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("at",            At.ToUniversalTime().ToString("o")),
                   new JProperty("station",       Station),
                   new JProperty("serialNumber",  SerialNumber),
                   new JProperty("responder",     Responder),
                   new JProperty("outcome",       Outcome),
                   new JProperty("detail",        Detail),
                   new JProperty("nextUpdate",    NextUpdate?.ToUniversalTime().ToString("o"))
               );

    }


    /// <summary>
    /// Whether a certificate is revoked, asked by a charging station of this
    /// CSMS - OCPP 2.0.1 and 2.1, M06, GetCertificateStatus - and asked on of
    /// the OCSP responder of the PKI: the station has no way to it but this
    /// CSMS, and needs the answer for the EV, which has none either.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The OCSP request is made of what the station names - the hashes of the
    /// issuer and the serial number - and sent to the responder it names; the
    /// answer goes back to it as it came, DER in Base64, for the station and
    /// the EV to judge by its signature.
    /// </para>
    /// <para>
    /// <b>Not to anywhere.</b> The responder is a station's word, and this CSMS
    /// asks it from inside its network: only one on the host of an EST server
    /// this CSMS sends CSRs to, or one named in "ocspResponders", is asked.
    /// Any other request is answered Failed, and the CSMS says so in its log.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// How many GetCertificateStatus requests are remembered, the newest first.
        /// </summary>
        public const Int32   CertificateStatusesKept   = 100;

        /// <summary>
        /// The longest an OCSP response may be to be handed on: the 18000
        /// characters of Base64 OCPP has every station take.
        /// </summary>
        public const Int32   MaxOCSPResultLength       = 18000;

        /// <summary>
        /// How long an OCSP responder has to answer.
        /// </summary>
        public static TimeSpan  OCSPTimeout           { get; } = TimeSpan.FromSeconds(10);

        private readonly List<CertificateStatusEntry>  certificateStatuses = [];

        #endregion

        #region Properties

        /// <summary>
        /// The GetCertificateStatus requests of the charging stations, the newest first.
        /// </summary>
        public IReadOnlyList<CertificateStatusEntry>  CertificateStatuses
        {
            get
            {
                lock (certificateStatuses)
                {
                    return [.. Enumerable.Reverse(certificateStatuses)];
                }
            }
        }

        #endregion


        #region (private) BuildCertificateStatus()

        /// <summary>
        /// Have GetCertificateStatus requests asked of the OCSP responder of
        /// the PKI - and not answered by the stand-in of the OCPP node.
        /// </summary>
        private void BuildCertificateStatus()
        {
            csms01.GetCertificateStatusProcessor = GetCertificateStatus;
        }

        #endregion

        #region (private) GetCertificateStatus(Timestamp, Sender, Connection, Request, CancellationToken)

        /// <summary>
        /// A charging station's GetCertificateStatus request: the OCSP
        /// responder it names asked, where this CSMS may, and its answer
        /// handed back.
        /// </summary>
        private async Task<GetCertificateStatusResponse> GetCertificateStatus(DateTimeOffset               Timestamp,
                                                                              IEventSender                 Sender,
                                                                              IMessageConnection           Connection,
                                                                              GetCertificateStatusRequest  Request,
                                                                              CancellationToken            CancellationToken)
        {

            var station    = Request.NetworkPath.Source.ToString();
            var data       = Request.OCSPRequestData;
            var serial     = data.SerialNumber;
            var responder  = data.ResponderURL.ToString();
            var now        = TimeProvider.GetUtcNow();

            GetCertificateStatusResponse Failed(String Outcome, String Why, String ReasonCode)
            {

                Remember(new CertificateStatusEntry(now, station, serial, responder, Outcome, Why));

                Log.Warning($"The GetCertificateStatus request of '{station}' for the certificate {serial} at '{responder}' was not answered: {Why}", "ocpp", "certificate", "station");

                return new GetCertificateStatusResponse(Request,
                                                        protocols.OCPPv2_1.GetCertificateStatus.Failed,
                                                        OCSPResult.Empty,
                                                        new StatusInfo(ReasonCode, Why.Length > 1024 ? Why[..1024] : Why));

            }

            #region Whether it may be asked, and what

            if (!Uri.TryCreate(responder, UriKind.Absolute, out var address) || !certificateSigning.MayAsk(address))
                return Failed("refused",
                              $"'{responder}' is no OCSP responder this CSMS asks: one on the host of the EST server of its PKI, or one it was told of.",
                              "UnknownResponder");

            if (!OCSPMessages.TryMakeRequest(data.HashAlgorithm.ToString(), data.IssuerNameHash, data.IssuerKeyHash, serial, out var ocspRequest, out var badRequest))
                return Failed("refused", badRequest, "InvalidOCSPRequest");

            #endregion

            #region Asked

            Byte[] answer;

            try
            {

                using var client  = PKIClient(address, OCSPTimeout);
                using var content = new ByteArrayContent(ocspRequest);

                content.Headers.ContentType = new MediaTypeHeaderValue(OCSPMessages.RequestContentType);

                using var request = new HttpRequestMessage(HttpMethod.Post, address) { Content = content };
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OCSPMessages.ResponseContentType));

                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, CancellationToken);

                if (!response.IsSuccessStatusCode)
                    return Failed("failed", $"'{responder}' answered HTTP {(Int32) response.StatusCode} {response.ReasonPhrase}.", "OCSPResponderFailed");

                // More than a station may be handed is not read at all.
                using var stream   = await response.Content.ReadAsStreamAsync(CancellationToken);
                using var buffer   = new MemoryStream();
                var       chunk    = new Byte[8192];
                var       maxBytes = MaxOCSPResultLength / 4 * 3;

                for (Int32 got; (got = await stream.ReadAsync(chunk, CancellationToken)) > 0;)
                {
                    buffer.Write(chunk, 0, got);
                    if (buffer.Length > maxBytes)
                        return Failed("failed", $"The answer of '{responder}' is longer than the {MaxOCSPResultLength} characters of Base64 a station takes.", "OCSPResponseTooLong");
                }

                answer = buffer.ToArray();

            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
            {
                return Failed("failed", $"'{responder}' could not be asked: {e.Message}", "OCSPResponderUnreachable");
            }

            #endregion

            #region Handed back

            if (!OCSPMessages.TryRead(answer, serial, out var read))
                return Failed("failed", $"What '{responder}' answered is no OCSP response.", "OCSPResponderFailed");

            if (read.ResponseStatus != "successful")
                return Failed("failed", $"'{responder}' answered {read.ResponseStatus}.", "OCSPResponderFailed");

            var outcome = read.CertificateStatus is "good" or "revoked" or "unknown" ? read.CertificateStatus : "answered";

            Remember(new CertificateStatusEntry(now, station, serial, responder, outcome,
                                                outcome == "answered" ? "The answer is not of the certificate asked about." : null,
                                                read.NextUpdate));

            if (outcome == "revoked")
                Log.Warning($"'{station}' asked about the certificate {serial}: '{responder}' says it was revoked{(read.RevokedAt is DateTimeOffset at ? $" on {at:u}" : "")}.", "ocpp", "certificate", "station");
            else
                Log.Info   ($"'{station}' asked about the certificate {serial}: '{responder}' says {outcome}.", "ocpp", "certificate", "station");

            return new GetCertificateStatusResponse(Request,
                                                    protocols.OCPPv2_1.GetCertificateStatus.Accepted,
                                                    OCSPResult.Parse(Convert.ToBase64String(answer)));

            #endregion

        }

        #endregion

        #region (private) Remember(Entry)

        private void Remember(CertificateStatusEntry Entry)
        {
            lock (certificateStatuses)
            {

                certificateStatuses.Add(Entry);

                if (certificateStatuses.Count > CertificateStatusesKept)
                    certificateStatuses.RemoveRange(0, certificateStatuses.Count - CertificateStatusesKept);

            }
        }

        #endregion

    }

}
