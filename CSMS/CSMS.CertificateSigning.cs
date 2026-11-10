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

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.OCPPv2_1;
using cloud.charging.open.protocols.OCPPv2_1.CS;
using cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.Configuration;

using OCPPCommon = cloud.charging.open.protocols.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// What became of one SignCertificate request of a charging station.
    /// </summary>
    /// <param name="At">When the station asked.</param>
    /// <param name="Station">The charging station, by its identity.</param>
    /// <param name="CertificateType">"ChargingStationCertificate" or "V2GCertificate".</param>
    /// <param name="Outcome">"signing", while it is at the PKI; "signed", once the station took the certificate; "rejected", where it was refused before it went anywhere; "failed", where the PKI did not sign it; "notTaken", where the station did not take what it was sent.</param>
    /// <param name="Detail">Why, in a sentence, where it was not signed; null otherwise.</param>
    /// <param name="Certificate">The SHA-256 fingerprint of the certificate signed; null where there is none.</param>
    /// <param name="NotAfter">Until when that certificate holds.</param>
    public sealed record CertificateSigningEntry(DateTimeOffset   At,
                                                 String           Station,
                                                 String           CertificateType,
                                                 String           Outcome,
                                                 String?          Detail        = null,
                                                 String?          Certificate   = null,
                                                 DateTimeOffset?  NotAfter      = null)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("at",               At.ToUniversalTime().ToString("o")),
                   new JProperty("station",          Station),
                   new JProperty("certificateType",  CertificateType),
                   new JProperty("outcome",          Outcome),
                   new JProperty("detail",           Detail),
                   new JProperty("certificate",      Certificate),
                   new JProperty("notAfter",         NotAfter?.ToUniversalTime().ToString("o"))
               );

    }


    /// <summary>
    /// The certificates of the charging stations, signed by a PKI: the CSR of
    /// a station's SignCertificate request - OCPP 2.0.1 and 2.1, A02 and A03 -
    /// sent to the EST server of the PKI, RFC 7030, and the certificate that
    /// comes back handed to the station with CertificateSigned.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The station is answered at once - Accepted, where the CSR is one this
    /// CSMS sends on, Rejected with the reason where it is not - and the
    /// certificate follows when the PKI has signed it, as OCPP has it: the
    /// station waits for CertificateSigned, and asks again where none comes.
    /// The chain sent is the certificate and the CAs above it, but for the
    /// root, which the station has already, or is given with InstallCertificate.
    /// </para>
    /// <para>
    /// A charging station's own certificate is its identity towards this CSMS,
    /// at security profile 3: its common name is the station's identity, and a
    /// CSR for any other name is refused - a station would otherwise be signed
    /// a certificate to sign in as another. A SECC certificate names the SECC,
    /// which this CSMS does not know, and is sent on as it is; what it may be
    /// is the PKI's to say, below its V2G sub-CA.
    /// </para>
    /// <para>
    /// One request of each kind for each station at a time: a station that asks
    /// again while its certificate is being signed is told so.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// What the server of a PKI is to this node, for its TLS root and for
        /// what it is judged by: see <c>JudgeServer</c>.
        /// </summary>
        public const String  PKIService                = "pki";

        /// <summary>
        /// How many SignCertificate requests are remembered, the newest first.
        /// </summary>
        public const Int32   CertificateSigningsKept   = 100;

        /// <summary>
        /// How long the PKI has to answer one request.
        /// </summary>
        public static TimeSpan  ESTTimeout            { get; } = TimeSpan.FromSeconds(30);

        private CertificateSigningConfiguration                                certificateSigning  = new ();

        private readonly List<CertificateSigningEntry>                        certificateSignings = [];

        private readonly ConcurrentDictionary<(String Station, String Type), Byte>  signingNow = new ();

        private readonly SemaphoreSlim                                         signingLock         = new (1, 1);

        #endregion

        #region Properties

        /// <summary>
        /// Where the CSRs of the charging stations go, as this CSMS has it now.
        /// </summary>
        public CertificateSigningConfiguration  CertificateSigning
            => certificateSigning;

        /// <summary>
        /// The SignCertificate requests of the charging stations, the newest first.
        /// </summary>
        public IReadOnlyList<CertificateSigningEntry>  CertificateSignings
        {
            get
            {
                lock (certificateSignings)
                {
                    return [.. Enumerable.Reverse(certificateSignings)];
                }
            }
        }

        #endregion


        #region (private) BuildCertificateSigning(Configuration)

        /// <summary>
        /// Have SignCertificate requests answered as the configuration file
        /// says - and not by the test CA of the OCPP node, which signs with a
        /// key nobody keeps.
        /// </summary>
        private void BuildCertificateSigning(CertificateSigningConfiguration? Configuration)
        {

            certificateSigning             = Configuration ?? new CertificateSigningConfiguration();
            csms01.SignCertificateProcessor = SignCertificate;

            BuildCertificateRenewal();
            BuildCertificateStatus();
            BuildStationRoots();

            Log.Info($"Certificate signing: {certificateSigning}.", "ocpp", "certificate");

        }

        #endregion

        #region TryUpdateCertificateSigning(JSON, out Error, out NotSaved)

        /// <summary>
        /// Change where the CSRs of the charging stations go: what the JSON says
        /// is changed, what it sets to null is removed, and what it does not
        /// name stays - the API key above all, which nobody reads back.
        /// </summary>
        /// <param name="NotSaved">True where the configuration file could not be written, and nothing was changed.</param>
        public Boolean TryUpdateCertificateSigning(JObject                           JSON,
                                                   [NotNullWhen(false)] out String?  Error,
                                                   out Boolean                       NotSaved)
        {

            NotSaved = false;

            if (!CertificateSigningConfiguration.TryParse(JSON, out var update, out Error))
                return false;

            var removed = JSON.Properties().Where(property => property.Value.Type == JTokenType.Null).Select(property => property.Name);

            signingLock.Wait();

            try
            {

                var updated = certificateSigning.Without(removed).Merge(update);

                if (!ConfigFile.TryReplaceSection(CertificateSigningConfiguration.SectionName, updated.ToJSON(), out Error))
                {
                    NotSaved = true;
                    return false;
                }

                certificateSigning = updated;

                Log.Notice($"Certificate signing was reconfigured: {updated}.", "ocpp", "certificate", "config");
                return true;

            }
            finally
            {
                signingLock.Release();
            }

        }

        #endregion

        #region CertificateSigningJSON()

        /// <summary>
        /// Where the CSRs go, whether there is an API key, how long before they
        /// run out the certificates are renewed - and the certificates of the
        /// stations, and what became of the latest requests.
        /// </summary>
        public JObject CertificateSigningJSON()
        {

            var json = certificateSigning.ToJSON(WithAPIKey: false);

            json["chargingStationCertificate"] ??= null;
            json["v2gCertificate"]             ??= null;
            json["renewDaysBefore"]              = (Int32) certificateSigning.RenewBefore.TotalDays;

            json.Add("certificates", new JArray(StationCertificates.All.Select(certificate => {
                                                    var one = certificate.ToJSON();
                                                    one.Add("renewsFrom", RenewsFrom(certificate)?.ToUniversalTime().ToString("o"));
                                                    one.Add("halfway",    IsHalfway(certificate));
                                                    one.Add("due",        IsDue(certificate));
                                                    one.Add("connected",  IsConnected(certificate.Station));
                                                    return one;
                                                })));

            json["ocspResponders"]             ??= new JArray();

            json.Add("requests", new JArray(CertificateSignings.Select(entry => entry.ToJSON())));
            json.Add("statusRequests", new JArray(CertificateStatuses.Select(entry => entry.ToJSON())));

            return json;

        }

        #endregion


        #region (private) SignCertificate(Timestamp, Sender, Connection, Request, CancellationToken)

        /// <summary>
        /// A charging station's SignCertificate request: answered at once, and
        /// the certificate sent on once the PKI has signed it.
        /// </summary>
        private Task<SignCertificateResponse> SignCertificate(DateTimeOffset      Timestamp,
                                                              IEventSender        Sender,
                                                              IMessageConnection  Connection,
                                                              SignCertificateRequest  Request,
                                                              CancellationToken   CancellationToken)
        {

            var station   = Request.NetworkPath.Source.ToString();
            var type      = Request.CertificateType ?? CertificateSigningUse.ChargingStationCertificate;
            var settings  = certificateSigning;
            var now       = TimeProvider.GetUtcNow();

            SignCertificateResponse Rejected(String ReasonCode, String Why)
            {

                Remember(new CertificateSigningEntry(now, station, type.ToString(), "rejected", Why));

                Log.Warning($"The SignCertificate request of '{station}' for a {type} was rejected: {Why}", "ocpp", "certificate", "station");

                return new SignCertificateResponse(Request,
                                                   GenericStatus.Rejected,
                                                   new StatusInfo(ReasonCode, Why.Length > 1024 ? Why[..1024] : Why));

            }

            #region Where it goes

            var est = type == CertificateSigningUse.ChargingStationCertificate ? settings.ChargingStationCertificate
                    : type == CertificateSigningUse.V2GCertificate             ? settings.V2GCertificate
                    : null;

            if (est is null)
                return Task.FromResult(Rejected("Unsupported",
                                                type == CertificateSigningUse.ChargingStationCertificate || type == CertificateSigningUse.V2GCertificate
                                                    ? $"This CSMS signs no {type}: it was told no PKI to send it to."
                                                    : $"This CSMS signs no {type}."));

            #endregion

            #region What it asks for

            CertificateRequest csr;

            try
            {
                // The signature checked here, so that a CSR that does not hold
                // is the station's to hear about, and not the PKI's.
                csr = CertificateRequest.LoadSigningRequestPem(Request.CSR, HashAlgorithmName.SHA256);
            }
            catch (Exception e) when (e is CryptographicException or ArgumentException)
            {
                return Task.FromResult(Rejected("InvalidCSR", $"The CSR is no PKCS#10 in PEM whose signature holds: {e.Message}"));
            }

            if (type == CertificateSigningUse.ChargingStationCertificate &&
                CommonNameOf(csr.SubjectName) is var commonName &&
                !String.Equals(commonName, station, StringComparison.Ordinal))
            {
                return Task.FromResult(Rejected("InvalidCSR",
                                                $"The CSR is for '{commonName ?? "no common name"}', and the certificate of a charging station names the station itself: '{station}'."));
            }

            #endregion

            var der = Convert.FromBase64String(Request.CSR[PemEncoding.Find(Request.CSR).Base64Data]);

            #region One at a time

            var key = (station, type.ToString());

            if (!signingNow.TryAdd(key, 0))
                return Task.FromResult(Rejected("Busy", $"A {type} of '{station}' is being signed already."));

            #endregion

            Remember(new CertificateSigningEntry(now, station, type.ToString(), "signing"));

            Log.Info($"'{station}' asked for a {type}: its CSR goes to {est}.", "ocpp", "certificate", "station");

            // Not awaited: the station is answered now, and the certificate
            // follows with a request of this CSMS's own.
            _ = Task.Run(async () => {
                    try
                    {
                        await SignAndSend(Request, der, type, est, settings.APIKey, now);
                    }
                    finally
                    {
                        signingNow.TryRemove(key, out _);
                    }
                });

            return Task.FromResult(new SignCertificateResponse(Request, GenericStatus.Accepted));

        }

        #endregion

        #region (private) SignAndSend(Request, CSR, Type, EST, APIKey, At)

        /// <summary>
        /// The CSR to the PKI, and the certificate it signs to the station.
        /// </summary>
        /// <param name="CSR">The CSR of the request, as DER.</param>
        private async Task SignAndSend(SignCertificateRequest  Request,
                                       Byte[]                  CSR,
                                       CertificateSigningUse   Type,
                                       Uri                     EST,
                                       String?                 APIKey,
                                       DateTimeOffset          At)
        {

            var station = Request.NetworkPath.Source.ToString();

            void Failed(String Outcome, String Why, String? Certificate = null, DateTimeOffset? NotAfter = null)
            {
                Remember(new CertificateSigningEntry(At, station, Type.ToString(), Outcome, Why, Certificate, NotAfter));
                Log.Warning($"The {Type} of '{station}' was not signed: {Why}", "ocpp", "certificate", "station");
            }

            #region Signed at the PKI

            X509Certificate2              certificate;
            List<X509Certificate2>        above;

            try
            {

                using var http   = PKIClient(EST);

                using var post   = new HttpRequestMessage(HttpMethod.Post, $"{EST}/simpleenroll") {
                                       Content = new StringContent(Convert.ToBase64String(CSR), Encoding.ASCII)
                                   };

                post.Content.Headers.ContentType = new MediaTypeHeaderValue("application/pkcs10");

                if (APIKey is not null)
                    post.Headers.Add("API-Key", APIKey);

                using var signed = await http.SendAsync(post);
                var answer       = await signed.Content.ReadAsStringAsync();

                if (!signed.IsSuccessStatusCode)
                {
                    Failed("failed", $"The PKI at {EST} answered {(Int32) signed.StatusCode}: {Shortened(answer)}");
                    return;
                }

                certificate      = CertificatesOf(answer).FirstOrDefault()
                                       ?? throw new CryptographicException("The PKI answered with no certificate.");

                using var cas    = await http.GetAsync($"{EST}/cacerts");

                above            = cas.IsSuccessStatusCode
                                       ? ChainAbove(certificate, CertificatesOf(await cas.Content.ReadAsStringAsync()))
                                       : [];

            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or CryptographicException or FormatException)
            {
                Failed("failed", $"The PKI at {EST} could not be asked: {e.Message}");
                return;
            }

            var fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();

            #endregion

            #region Sent to the station

            try
            {

                var pem      = String.Concat(new[] { certificate }.Concat(above).Select(one => PemEncoding.WriteString("CERTIFICATE", one.RawData) + "\n"));

                var response = await csms01.OCPP.OUT.CertificateSigned(
                                         new CertificateSignedRequest(
                                             SourceRouting.To(Request.NetworkPath.Source),
                                             OCPPCommon.CertificateChain.Parse(pem),
                                             Type,
                                             Request.SignCertificateRequestId
                                         )
                                     );

                if (response.Status.ToString() != "Accepted")
                {
                    Failed("notTaken",
                           $"'{station}' did not take the certificate {fingerprint}: {response.Status}{(response.StatusInfo is null ? "" : $", {response.StatusInfo.ReasonCode} {response.StatusInfo.AdditionalInfo}")}.",
                           fingerprint, certificate.NotAfter);
                    return;
                }

                Remember(new CertificateSigningEntry(At, station, Type.ToString(), "signed", null, fingerprint, certificate.NotAfter));

                StationCertificates.Note(station, Type.ToString(), fingerprint, certificate.NotAfter.ToUniversalTime(), "signed", TimeProvider.GetUtcNow(),
                                         certificate.NotBefore.ToUniversalTime(),
                                         certificate.SerialNumber);

                Log.Notice($"'{station}' took the {Type} {fingerprint}, signed by '{certificate.Issuer}' and valid until {certificate.NotAfter.ToUniversalTime():u}.",
                           "ocpp", "certificate", "station", "security");

            }
            catch (Exception e)
            {
                Failed("notTaken", $"The certificate {fingerprint} could not be sent to '{station}': {e.Message}", fingerprint, certificate.NotAfter);
            }
            finally
            {
                certificate.Dispose();
                foreach (var ca in above)
                    ca.Dispose();
            }

            #endregion

        }

        #endregion

        #region (private) PKIClient(Address, Timeout = null)

        /// <summary>
        /// An HTTP client for the PKI - its EST server, its OCSP responder: its
        /// name looked up by the DNS client of this node, and its certificate
        /// judged by this node - the machine's roots and the TLS roots of this
        /// node's own store for "pki" - as the name and the time servers are.
        /// </summary>
        private HttpClient PKIClient(Uri Address, TimeSpan? Timeout = null)
        {

            var handler = NameResolution.HTTPHandler(DNSClient);

            handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => {

                using var shown = certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

                return JudgeServer(PKIService,
                                   Address.Host,
                                   null,
                                   shown,
                                   chain,
                                   errors,
                                   Evidence: false).Accepted;

            };

            return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout ?? ESTTimeout };

        }

        #endregion

        #region (private static) CertificatesOf(Answer) / ChainAbove(Certificate, CAs)

        /// <summary>
        /// The certificates of a certs-only PKCS#7 in Base64, as EST answers.
        /// </summary>
        private static List<X509Certificate2> CertificatesOf(String Answer)
        {

            var cms = new SignedCms();
            cms.Decode(Convert.FromBase64String(new String(Answer.Where(character => !Char.IsWhiteSpace(character)).ToArray())));

            return [.. cms.Certificates.Cast<X509Certificate2>()];

        }

        /// <summary>
        /// The CAs above a certificate, from its issuer up and without the
        /// root: what a chain sent to a station has.
        /// </summary>
        private static List<X509Certificate2> ChainAbove(X509Certificate2        Certificate,
                                                         List<X509Certificate2>  CAs)
        {

            var chain    = new List<X509Certificate2>();
            var current  = Certificate;

            while (CAs.FirstOrDefault(ca => ca.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData)) is X509Certificate2 issuer &&
                   !chain.Contains(issuer))
            {

                if (issuer.SubjectName.RawData.AsSpan().SequenceEqual(issuer.IssuerName.RawData))
                    break;

                chain.Add(issuer);
                current = issuer;

            }

            foreach (var ca in CAs.Except(chain))
                ca.Dispose();

            return chain;

        }

        #endregion

        #region (private) Remember(Entry)

        /// <summary>
        /// What became of a request - in place of what was said of it while it
        /// was at the PKI.
        /// </summary>
        private void Remember(CertificateSigningEntry Entry)
        {
            lock (certificateSignings)
            {

                certificateSignings.RemoveAll(one => one.Outcome         == "signing"   &&
                                                     one.At              == Entry.At    &&
                                                     one.Station         == Entry.Station &&
                                                     one.CertificateType == Entry.CertificateType);

                certificateSignings.Add(Entry);

                if (certificateSignings.Count > CertificateSigningsKept)
                    certificateSignings.RemoveRange(0, certificateSignings.Count - CertificateSigningsKept);

            }
        }

        #endregion

        #region (private static) CommonNameOf(Name) / Shortened(Text)

        private static String? CommonNameOf(X500DistinguishedName Name)
        {

            foreach (var part in Name.EnumerateRelativeDistinguishedNames())
                if (!part.HasMultipleElements && part.GetSingleElementType().Value == "2.5.4.3")
                    return part.GetSingleElementValue();

            return null;

        }

        private static String Shortened(String Text)
        {
            var text = Text.Trim();
            return text.Length > 300 ? text[..300] + "..." : text;
        }

        #endregion

    }

}
