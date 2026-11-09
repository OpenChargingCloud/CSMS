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
using System.Formats.Asn1;

#endregion

namespace cloud.charging.open.CSMS.OCPP
{

    /// <summary>
    /// What an OCSP responder said of one certificate, as far as this CSMS
    /// reads it: it hands the answer on to the station as it came, and keeps
    /// this for its own page.
    /// </summary>
    /// <param name="ResponseStatus">The responseStatus of RFC 6960: "successful", "malformedRequest", "internalError", "tryLater", "sigRequired", "unauthorized".</param>
    /// <param name="CertificateStatus">"good", "revoked" or "unknown"; null where the answer was not successful, or names no such certificate.</param>
    /// <param name="RevokedAt">When it was revoked, where it was.</param>
    /// <param name="NextUpdate">Until when the answer holds, where the responder says so.</param>
    public sealed record OCSPAnswer(String           ResponseStatus,
                                    String?          CertificateStatus   = null,
                                    DateTimeOffset?  RevokedAt           = null,
                                    DateTimeOffset?  NextUpdate          = null);


    /// <summary>
    /// The OCSP of RFC 6960 as far as a CSMS needs it to ask on behalf of its
    /// stations: a request made of what a station's GetCertificateStatus says
    /// - OCPP 2.0.1 and 2.1, M06 - and the answer read for what it says of the
    /// certificate.
    /// </summary>
    /// <remarks>
    /// The answer is not judged here - its signature, its responder: that is
    /// the station's to do, and the EV's, which it is handed on to. What this
    /// CSMS reads of it is what it shows on its page, and nothing that lets a
    /// station in or keeps one out.
    /// </remarks>
    public static class OCSPMessages
    {

        #region Data

        /// <summary>
        /// The content types of RFC 6960, appendix A.
        /// </summary>
        public const String RequestContentType   = "application/ocsp-request";
        public const String ResponseContentType  = "application/ocsp-response";

        /// <summary>
        /// id-pkix-ocsp-basic.
        /// </summary>
        public const String BasicResponseOID     = "1.3.6.1.5.5.7.48.1.1";

        private static readonly Asn1Tag Context0  = new (TagClass.ContextSpecific, 0);
        private static readonly Asn1Tag Context1  = new (TagClass.ContextSpecific, 1);
        private static readonly Asn1Tag Context2  = new (TagClass.ContextSpecific, 2);

        #endregion


        #region HashAlgorithmOID(Name) / HashLength(Name)

        /// <summary>
        /// The OID of a hash algorithm, as OCPP names it; null for one it does
        /// not name.
        /// </summary>
        public static String? HashAlgorithmOID(String Name)

            => Name.ToUpperInvariant() switch {
                   "SHA256"  => "2.16.840.1.101.3.4.2.1",
                   "SHA384"  => "2.16.840.1.101.3.4.2.2",
                   "SHA512"  => "2.16.840.1.101.3.4.2.3",
                   _         => null
               };

        /// <summary>
        /// How many bytes a hash of it has.
        /// </summary>
        public static Int32 HashLength(String Name)

            => Name.ToUpperInvariant() switch {
                   "SHA256"  => 32,
                   "SHA384"  => 48,
                   "SHA512"  => 64,
                   _         => 0
               };

        #endregion

        #region TryMakeRequest(HashAlgorithm, IssuerNameHash, IssuerKeyHash, SerialNumber, out Request, out Error)

        /// <summary>
        /// An OCSP request for one certificate, as a GetCertificateStatus
        /// names it: the hashes and the serial number in hexadecimal.
        /// </summary>
        public static Boolean TryMakeRequest(String                            HashAlgorithm,
                                             String                            IssuerNameHash,
                                             String                            IssuerKeyHash,
                                             String                            SerialNumber,
                                             [NotNullWhen(true)]  out Byte[]?  Request,
                                             [NotNullWhen(false)] out String?  Error)
        {

            Request  = null;
            Error    = null;

            if (HashAlgorithmOID(HashAlgorithm) is not String oid)
            {
                Error = $"'{HashAlgorithm}' is no hash algorithm of OCPP: SHA256, SHA384 or SHA512.";
                return false;
            }

            if (!TryHex(IssuerNameHash, out var nameHash) || nameHash.Length != HashLength(HashAlgorithm) ||
                !TryHex(IssuerKeyHash,  out var keyHash)  || keyHash. Length != HashLength(HashAlgorithm))
            {
                Error = $"The hashes of the issuer are not those of {HashAlgorithm}: {HashLength(HashAlgorithm)} bytes in hexadecimal each.";
                return false;
            }

            if (!TryHex(SerialNumber.Length % 2 == 1 ? "0" + SerialNumber : SerialNumber, out var serial) || serial.Length is 0 or > 20)
            {
                Error = "The serial number is not one of a certificate: up to 20 bytes in hexadecimal.";
                return false;
            }

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())                       // OCSPRequest
            using (writer.PushSequence())                       //   TBSRequest
            using (writer.PushSequence())                       //     requestList
            using (writer.PushSequence())                       //       Request
            using (writer.PushSequence())                       //         CertID
            {

                using (writer.PushSequence())                   //           hashAlgorithm
                {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteNull();
                }

                writer.WriteOctetString(nameHash);
                writer.WriteOctetString(keyHash);
                writer.WriteIntegerUnsigned(serial);

            }

            Request = writer.Encode();
            return true;

        }

        #endregion

        #region TryRead(Response, SerialNumber, out Answer)

        /// <summary>
        /// What an OCSP response says of the certificate of the given serial
        /// number, in hexadecimal; false where it is no OCSP response at all.
        /// </summary>
        public static Boolean TryRead(ReadOnlyMemory<Byte>                   Response,
                                      String                                 SerialNumber,
                                      [NotNullWhen(true)] out OCSPAnswer?    Answer)
        {

            Answer = null;

            try
            {

                var response  = new AsnReader(Response, AsnEncodingRules.DER).ReadSequence();
                var status    = response.ReadEnumeratedValue<OCSPResponseStatus>();
                var named     = Char.ToLowerInvariant(status.ToString()[0]) + status.ToString()[1..];

                if (status != OCSPResponseStatus.Successful || !response.HasData)
                {
                    Answer = new OCSPAnswer(named);
                    return true;
                }

                var bytes     = response.ReadSequence(Context0).ReadSequence();

                if (bytes.ReadObjectIdentifier() != BasicResponseOID)
                {
                    Answer = new OCSPAnswer(named);
                    return true;
                }

                var basic     = new AsnReader(bytes.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
                var data      = basic.ReadSequence();

                if (data.PeekTag().HasSameClassAndValue(Context0))
                    data.ReadSequence(Context0);                    // version

                data.ReadEncodedValue();                            // responderID
                data.ReadGeneralizedTime();                         // producedAt

                var responses = data.ReadSequence();
                var wanted    = SerialNumber.TrimStart('0').ToLowerInvariant();

                OCSPAnswer? first = null;

                while (responses.HasData)
                {

                    var single  = responses.ReadSequence();
                    var certID  = single.ReadSequence();

                    certID.ReadSequence();                          // hashAlgorithm
                    certID.ReadOctetString();                       // issuerNameHash
                    certID.ReadOctetString();                       // issuerKeyHash

                    var serial  = Convert.ToHexString(certID.ReadIntegerBytes().Span).TrimStart('0').ToLowerInvariant();

                    var tag     = single.PeekTag();
                    String           certificateStatus;
                    DateTimeOffset?  revokedAt = null;

                    if (tag.HasSameClassAndValue(Context1))
                    {
                        certificateStatus = "revoked";
                        revokedAt         = single.ReadSequence(Context1).ReadGeneralizedTime();
                    }
                    else
                    {
                        certificateStatus = tag.HasSameClassAndValue(Context0) ? "good"
                                          : tag.HasSameClassAndValue(Context2) ? "unknown"
                                          : "?";
                        single.ReadEncodedValue();
                    }

                    single.ReadGeneralizedTime();                   // thisUpdate

                    DateTimeOffset? nextUpdate = null;

                    if (single.HasData && single.PeekTag().HasSameClassAndValue(Context0))
                        nextUpdate = single.ReadSequence(Context0).ReadGeneralizedTime();

                    var answer = new OCSPAnswer(named, certificateStatus, revokedAt, nextUpdate);

                    if (serial == wanted)
                    {
                        Answer = answer;
                        return true;
                    }

                    first ??= answer;

                }

                // An answer for another certificate than the one asked: said
                // as it is, and of none.
                Answer = new OCSPAnswer(named, first is null ? null : "?");
                return true;

            }
            catch (Exception e) when (e is AsnContentException or ArgumentException or InvalidOperationException or FormatException)
            {
                return false;
            }

        }

        #endregion


        #region (private) TryHex(Text, out Bytes)

        private static Boolean TryHex(String Text, out Byte[] Bytes)
        {

            Bytes = [];

            var text = Text.Trim();

            if (text.Length == 0 || text.Length % 2 == 1 || !text.All(Uri.IsHexDigit))
                return false;

            Bytes = Convert.FromHexString(text);
            return true;

        }

        #endregion

        #region (private) OCSPResponseStatus

        /// <summary>
        /// The responseStatus of RFC 6960.
        /// </summary>
        private enum OCSPResponseStatus
        {
            Successful        = 0,
            MalformedRequest  = 1,
            InternalError     = 2,
            TryLater          = 3,
            SigRequired       = 5,
            Unauthorized      = 6
        }

        #endregion

    }

}
