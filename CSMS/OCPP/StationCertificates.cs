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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.CSMS.Web;

#endregion

namespace cloud.charging.open.CSMS.OCPP
{

    /// <summary>
    /// A certificate a charging station has, as this CSMS knows of it - and
    /// what came of asking the station to renew it.
    /// </summary>
    /// <param name="Station">The charging station, by its identity.</param>
    /// <param name="CertificateType">"ChargingStationCertificate" or "V2GCertificate".</param>
    /// <param name="Fingerprint">The SHA-256 fingerprint of the certificate, in lower case.</param>
    /// <param name="NotAfter">Until when it holds.</param>
    /// <param name="Source">"signed", where this CSMS had it signed and the station took it; "presented", where the station signed in with it.</param>
    /// <param name="Noted">When this CSMS first knew of it.</param>
    /// <param name="RenewalAsked">When the station was last asked for a new one, for this certificate.</param>
    /// <param name="RenewalAnswer">What the station answered: "Accepted", "Rejected", "NotImplemented" - or why it could not be asked.</param>
    /// <param name="NotBefore">From when it holds; not known of the certificates noted before it was kept.</param>
    /// <param name="SerialNumber">Its serial number in hexadecimal, as X.509 writes it; not known of the certificates noted before it was kept.</param>
    public sealed record StationCertificate(String           Station,
                                            String           CertificateType,
                                            String           Fingerprint,
                                            DateTimeOffset   NotAfter,
                                            String           Source,
                                            DateTimeOffset   Noted,
                                            DateTimeOffset?  RenewalAsked    = null,
                                            String?          RenewalAnswer   = null,
                                            DateTimeOffset?  NotBefore       = null,
                                            String?          SerialNumber    = null)
    {

        /// <summary>
        /// Whether this is the certificate of the given serial number, in
        /// hexadecimal of either case, with leading zeros or without.
        /// </summary>
        public Boolean HasSerialNumber(String Serial)

            => SerialNumber is not null &&
               String.Equals(SerialNumber.TrimStart('0'), Serial.Trim().TrimStart('0'), StringComparison.OrdinalIgnoreCase);


        public JObject ToJSON()

            => new (
                   new JProperty("station",          Station),
                   new JProperty("certificateType",  CertificateType),
                   new JProperty("fingerprint",      Fingerprint),
                   new JProperty("serialNumber",     SerialNumber),
                   new JProperty("notBefore",        NotBefore?.ToUniversalTime().ToString("o")),
                   new JProperty("notAfter",         NotAfter.ToUniversalTime().ToString("o")),
                   new JProperty("source",           Source),
                   new JProperty("noted",            Noted.ToUniversalTime().ToString("o")),
                   new JProperty("renewalAsked",     RenewalAsked?.ToUniversalTime().ToString("o")),
                   new JProperty("renewalAnswer",    RenewalAnswer)
               );

        public static StationCertificate? TryParse(JToken JSON)
        {
            try
            {

                var station      = JSON["station"]?.        Value<String>();
                var type         = JSON["certificateType"]?.Value<String>();
                var fingerprint  = JSON["fingerprint"]?.    Value<String>();
                var source       = JSON["source"]?.         Value<String>();

                if (String.IsNullOrEmpty(station) || String.IsNullOrEmpty(type) || String.IsNullOrEmpty(fingerprint) || String.IsNullOrEmpty(source) ||
                    JSON["notAfter"] is not JToken notAfter || JSON["noted"] is not JToken noted)
                {
                    return null;
                }

                return new StationCertificate(station,
                                              type,
                                              fingerprint,
                                              DateTimeOffset.Parse(notAfter.Value<String>()!, null, System.Globalization.DateTimeStyles.RoundtripKind),
                                              source,
                                              DateTimeOffset.Parse(noted.   Value<String>()!, null, System.Globalization.DateTimeStyles.RoundtripKind),
                                              JSON["renewalAsked"] is JToken asked && asked.Type != JTokenType.Null
                                                  ? DateTimeOffset.Parse(asked.Value<String>()!, null, System.Globalization.DateTimeStyles.RoundtripKind)
                                                  : null,
                                              JSON["renewalAnswer"]?.Type == JTokenType.String ? JSON["renewalAnswer"]!.Value<String>() : null,
                                              JSON["notBefore"] is JToken notBefore && notBefore.Type != JTokenType.Null
                                                  ? DateTimeOffset.Parse(notBefore.Value<String>()!, null, System.Globalization.DateTimeStyles.RoundtripKind)
                                                  : null,
                                              JSON["serialNumber"]?.Type == JTokenType.String ? JSON["serialNumber"]!.Value<String>() : null);

            }
            catch (Exception e) when (e is FormatException or InvalidCastException or ArgumentException)
            {
                return null;
            }
        }

    }


    /// <summary>
    /// The certificates of the charging stations this CSMS knows of - one of
    /// each kind for each station - so that it may ask for a new one before the
    /// old one runs out.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Its own file.</b> What a station's certificate is outlives this
    /// process: a certificate signed in March runs out in March of the next
    /// year, and a CSMS restarted in between must still know to renew it. It
    /// holds no secret - fingerprints and dates - and is written for its owner
    /// all the same, as everything beside it is.
    /// </para>
    /// <para>
    /// <b>The later certificate wins.</b> A station that took a new
    /// certificate and still signs in with the old one, until it switches, is
    /// not to be asked for yet another: what is kept is the certificate that
    /// holds the longest, whichever way it became known.
    /// </para>
    /// <para>
    /// <b>A file that cannot be read is put aside</b>, and not a reason to
    /// stop: nothing in here lets a station in or keeps one out, and what it
    /// forgot is learned again as the stations sign in and are signed.
    /// </para>
    /// </remarks>
    public sealed class StationCertificates
    {

        #region Data

        /// <summary>
        /// The name of the file beside the configuration file.
        /// </summary>
        public const String  DefaultFileName  = "ocpp-station-certificates.json";

        private readonly Dictionary<(String Station, String Type), StationCertificate>  certificates = new ();

        private readonly Object  updateLock  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Where they are kept.
        /// </summary>
        public String  Path    { get; }

        /// <summary>
        /// Every certificate known of, by station and kind.
        /// </summary>
        public IReadOnlyList<StationCertificate> All
        {
            get
            {
                lock (updateLock)
                {
                    return [.. certificates.Values.OrderBy(certificate => certificate.Station, StringComparer.OrdinalIgnoreCase).
                                                   ThenBy (certificate => certificate.CertificateType, StringComparer.Ordinal)];
                }
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Something happened here that belongs in the log of the CSMS.
        /// </summary>
        public event Action<LogLevel, String>? OnNotice;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The certificates in the given file; it need not exist yet.
        /// </summary>
        public StationCertificates(String? Path = null)
        {
            this.Path = System.IO.Path.GetFullPath(Path ?? DefaultFileName);
        }

        #endregion


        #region Load()

        /// <summary>
        /// Read the file, where there is one; one that cannot be read is moved
        /// aside, said so, and started over.
        /// </summary>
        public void Load()
        {

            lock (updateLock)
            {

                certificates.Clear();

                if (!File.Exists(Path))
                    return;

                try
                {

                    var text = File.ReadAllText(Path);

                    if (String.IsNullOrWhiteSpace(text))
                        return;

                    // The dates as they were written, not as Newtonsoft
                    // would read them: as a DateTime of the local time zone.
                    using var reader = new JsonTextReader(new StringReader(text)) { DateParseHandling = DateParseHandling.None };

                    foreach (var entry in JObject.Load(reader)["certificates"] as JArray ?? [])
                        if (StationCertificate.TryParse(entry) is StationCertificate certificate)
                            certificates[(certificate.Station, certificate.CertificateType)] = certificate;

                }
                catch (Exception e)
                {

                    var aside = Path + ".unreadable";

                    try
                    {
                        File.Move(Path, aside, overwrite: true);
                    }
                    catch (Exception)
                    { }

                    certificates.Clear();

                    OnNotice?.Invoke(LogLevel.Warning,
                                     $"'{Path}' could not be read, and was put aside as '{aside}': {e.Message} " +
                                     "The certificates of the charging stations are learned again as they sign in and are signed.");

                }

            }

        }

        #endregion

        #region Get(Station, CertificateType)

        public StationCertificate? Get(String Station, String CertificateType)
        {
            lock (updateLock)
            {
                return certificates.TryGetValue((Station, CertificateType), out var certificate) ? certificate : null;
            }
        }

        #endregion

        #region Note(Station, CertificateType, Fingerprint, NotAfter, Source, At, NotBefore = null, SerialNumber = null)

        /// <summary>
        /// A certificate of a station: kept where it is the first of its kind,
        /// or holds longer than the one known.
        /// </summary>
        /// <returns>Whether it is the one kept now.</returns>
        public Boolean Note(String           Station,
                            String           CertificateType,
                            String           Fingerprint,
                            DateTimeOffset   NotAfter,
                            String           Source,
                            DateTimeOffset   At,
                            DateTimeOffset?  NotBefore     = null,
                            String?          SerialNumber  = null)
        {

            lock (updateLock)
            {

                if (certificates.TryGetValue((Station, CertificateType), out var known) &&
                    (known.Fingerprint == Fingerprint || known.NotAfter > NotAfter))
                {

                    // Known from before its first day and its serial number
                    // were kept: learned now.
                    if (known.Fingerprint == Fingerprint &&
                        ((known.NotBefore is null && NotBefore is not null) || (known.SerialNumber is null && SerialNumber is not null)))
                    {
                        certificates[(Station, CertificateType)] = known with { NotBefore     = known.NotBefore    ?? NotBefore,
                                                                                SerialNumber  = known.SerialNumber ?? SerialNumber };
                        Save();
                    }

                    return known.Fingerprint == Fingerprint;

                }

                certificates[(Station, CertificateType)] = new StationCertificate(Station, CertificateType, Fingerprint, NotAfter, Source, At, NotBefore: NotBefore, SerialNumber: SerialNumber);

                Save();
                return true;

            }

        }

        #endregion

        #region Forget(Station, CertificateType = null)

        /// <summary>
        /// Forget the certificate of the given kind of a station - or all of
        /// its certificates: the station is gone, or the certificate is not the
        /// station's to be renewed any more.
        /// </summary>
        /// <returns>How many were forgotten.</returns>
        public Int32 Forget(String   Station,
                            String?  CertificateType   = null)
        {

            lock (updateLock)
            {

                var gone = certificates.Keys.Where(key => key.Station == Station &&
                                                          (CertificateType is null || key.Type == CertificateType)).
                                             ToList();

                foreach (var key in gone)
                    certificates.Remove(key);

                if (gone.Count > 0)
                    Save();

                return gone.Count;

            }

        }

        #endregion

        #region NoteAsked(Station, CertificateType, At, Answer)

        /// <summary>
        /// The station was asked to renew its certificate, and answered so - or
        /// could not be asked, and why.
        /// </summary>
        public void NoteAsked(String          Station,
                              String          CertificateType,
                              DateTimeOffset  At,
                              String          Answer)
        {

            lock (updateLock)
            {

                if (!certificates.TryGetValue((Station, CertificateType), out var known))
                    return;

                certificates[(Station, CertificateType)] = known with { RenewalAsked = At, RenewalAnswer = Answer };

                Save();

            }

        }

        #endregion


        #region (private) Save()

        /// <summary>
        /// Written whole, to a file beside it first and moved over it; what
        /// cannot be written is said, and kept in memory all the same.
        /// </summary>
        private void Save()
        {

            try
            {

                var directory = System.IO.Path.GetDirectoryName(Path);

                if (!String.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);

                var temporary = Path + ".tmp";

                OwnerOnlyFile.Write(
                    temporary,
                    new JObject(
                        new JProperty("certificates", new JArray(
                            certificates.Values.OrderBy(certificate => certificate.Station, StringComparer.OrdinalIgnoreCase).
                                                ThenBy (certificate => certificate.CertificateType, StringComparer.Ordinal).
                                                Select (certificate => certificate.ToJSON())
                        ))
                    ).ToString(Formatting.Indented) + Environment.NewLine,
                    problem => OnNotice?.Invoke(LogLevel.Warning, problem)
                );

                File.Move(temporary, Path, overwrite: true);

            }
            catch (Exception e)
            {
                OnNotice?.Invoke(LogLevel.Warning, $"'{Path}' could not be written: {e.Message}");
            }

        }

        #endregion

    }

}
