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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.CSMS.Web;

#endregion

namespace cloud.charging.open.CSMS.OCPP
{

    /// <summary>
    /// A root certificate for the charging stations - one they are to trust
    /// for what its kind says - as this CSMS keeps it to install.
    /// </summary>
    /// <param name="Id">The SHA-256 fingerprint of the certificate, in lower case.</param>
    /// <param name="CertificateType">What it is to the station, as InstallCertificate names it: "CSMSRootCertificate", "V2GRootCertificate", "MORootCertificate", "ManufacturerRootCertificate", "OEMRootCertificate".</param>
    /// <param name="PEM">The certificate.</param>
    /// <param name="Subject">Its subject, as X.500 writes it.</param>
    /// <param name="SerialNumber">Its serial number in hexadecimal, as X.509 writes it.</param>
    /// <param name="NotAfter">Until when it holds.</param>
    /// <param name="Added">When it was added.</param>
    /// <param name="Everywhere">Whether every station is to have it: installed where it is missing, when a station starts.</param>
    public sealed record StationRoot(String          Id,
                                     String          CertificateType,
                                     String          PEM,
                                     String          Subject,
                                     String          SerialNumber,
                                     DateTimeOffset  NotAfter,
                                     DateTimeOffset  Added,
                                     Boolean         Everywhere)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("id",               Id),
                   new JProperty("certificateType",  CertificateType),
                   new JProperty("subject",          Subject),
                   new JProperty("serialNumber",     SerialNumber),
                   new JProperty("notAfter",         NotAfter.ToUniversalTime().ToString("o")),
                   new JProperty("added",            Added.   ToUniversalTime().ToString("o")),
                   new JProperty("everywhere",       Everywhere),
                   new JProperty("pem",              PEM)
               );

        public static StationRoot? TryParse(JToken JSON)
        {
            try
            {

                var pem   = JSON["pem"]?.            Value<String>();
                var type  = JSON["certificateType"]?.Value<String>();

                if (String.IsNullOrEmpty(pem) || String.IsNullOrEmpty(type) ||
                    !StationRoots.TryRead(pem, out var certificate, out _))
                {
                    return null;
                }

                using (certificate)
                {
                    return StationRoots.RootOf(certificate,
                                               type,
                                               JSON["added"] is JToken added && added.Type == JTokenType.String
                                                   ? DateTimeOffset.Parse(added.Value<String>()!, null, System.Globalization.DateTimeStyles.RoundtripKind)
                                                   : DateTimeOffset.UtcNow,
                                               JSON["everywhere"]?.Type == JTokenType.Boolean && JSON["everywhere"]!.Value<Boolean>());
                }

            }
            catch (Exception e) when (e is FormatException or InvalidCastException or ArgumentException)
            {
                return null;
            }
        }

        /// <summary>
        /// Whether a certificate a station says it has - by its hashes and
        /// serial number, as GetInstalledCertificateIds names it - is this one.
        /// </summary>
        public Boolean Is(String  HashAlgorithm,
                          String  IssuerNameHash,
                          String  IssuerKeyHash,
                          String  Serial)
        {

            if (StationRoots.HashesOf(PEM, HashAlgorithm) is not (String nameHash, String keyHash))
                return false;

            return String.Equals(nameHash, IssuerNameHash.Trim(), StringComparison.OrdinalIgnoreCase) &&
                   String.Equals(keyHash,  IssuerKeyHash. Trim(), StringComparison.OrdinalIgnoreCase) &&
                   String.Equals(SerialNumber.TrimStart('0'), Serial.Trim().TrimStart('0'), StringComparison.OrdinalIgnoreCase);

        }

    }


    /// <summary>
    /// The root certificates this CSMS installs on its charging stations, with
    /// InstallCertificate, OCPP 2.0.1 and 2.1, M05: the root its own TLS
    /// certificate is below, the V2G root of ISO 15118, the roots of mobility
    /// operators and of manufacturers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Roots only.</b> A station keeps what it is to trust by kind, and
    /// a kind holds roots: a certificate here is a CA that signed itself. Its
    /// key is nobody's business here, and nothing in the file is a secret.
    /// </para>
    /// <para>
    /// <b>Everywhere, or where it is put.</b> A root marked "everywhere" is
    /// installed on every station that starts without it - the new root of a
    /// rollover is on the stations before their first certificate below it is.
    /// Any other is installed by hand, on one station or on all connected.
    /// </para>
    /// </remarks>
    public sealed class StationRoots
    {

        #region Data

        /// <summary>
        /// The name of the file beside the configuration file.
        /// </summary>
        public const String  DefaultFileName  = "ocpp-station-roots.json";

        /// <summary>
        /// The kinds of root certificate a station is installed, as OCPP 2.1
        /// names them; OCPP 2.0.1 knows the first four.
        /// </summary>
        public static readonly IReadOnlyList<String> CertificateTypes = [
            "CSMSRootCertificate",
            "V2GRootCertificate",
            "MORootCertificate",
            "ManufacturerRootCertificate",
            "OEMRootCertificate"
        ];

        /// <summary>
        /// The most roots kept.
        /// </summary>
        public const Int32  MaxRoots  = 64;

        private readonly Dictionary<(String Id, String Type), StationRoot>  roots       = new ();
        private readonly Object                                            updateLock  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Where they are kept.
        /// </summary>
        public String  Path    { get; }

        /// <summary>
        /// Every root, by kind and subject.
        /// </summary>
        public IReadOnlyList<StationRoot> All
        {
            get
            {
                lock (updateLock)
                {
                    return [.. roots.Values.OrderBy(root => CertificateTypes.ToList().IndexOf(root.CertificateType)).
                                            ThenBy (root => root.Subject, StringComparer.OrdinalIgnoreCase).
                                            ThenBy (root => root.NotAfter)];
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

        public StationRoots(String? Path = null)
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

                roots.Clear();

                if (!File.Exists(Path))
                    return;

                try
                {

                    var text = File.ReadAllText(Path);

                    if (String.IsNullOrWhiteSpace(text))
                        return;

                    using var reader = new JsonTextReader(new StringReader(text)) { DateParseHandling = DateParseHandling.None };

                    foreach (var entry in JObject.Load(reader)["roots"] as JArray ?? [])
                        if (StationRoot.TryParse(entry) is StationRoot root)
                            roots[(root.Id, root.CertificateType)] = root;

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

                    roots.Clear();

                    OnNotice?.Invoke(LogLevel.Warning,
                                     $"'{Path}' could not be read, and was put aside as '{aside}': {e.Message} " +
                                     "No root certificate is installed on the charging stations until they are added again.");

                }

            }

        }

        #endregion

        #region Get(Id, CertificateType = null)

        /// <summary>
        /// The root of the given fingerprint - of the given kind, or of any.
        /// </summary>
        public StationRoot? Get(String Id, String? CertificateType = null)
        {
            lock (updateLock)
            {
                return roots.Values.FirstOrDefault(root => root.Id == Id.Trim().ToLowerInvariant() &&
                                                           (CertificateType is null || root.CertificateType == CertificateType));
            }
        }

        #endregion

        #region TryAdd(PEM, CertificateType, Everywhere, At, out Root, out Error)

        /// <summary>
        /// Add a root certificate of the given kind.
        /// </summary>
        public Boolean TryAdd(String                                 PEM,
                              String                                 CertificateType,
                              Boolean                                Everywhere,
                              DateTimeOffset                         At,
                              [NotNullWhen(true)]  out StationRoot?  Root,
                              [NotNullWhen(false)] out String?       Error)
        {

            Root = null;

            if (!CertificateTypes.Contains(CertificateType))
            {
                Error = $"'{CertificateType}' is no kind of root a station is installed: {String.Join(", ", CertificateTypes)}.";
                return false;
            }

            if (!TryRead(PEM, out var certificate, out Error))
                return false;

            using (certificate)
            {

                var root = RootOf(certificate, CertificateType, At, Everywhere);

                lock (updateLock)
                {

                    if (roots.ContainsKey((root.Id, root.CertificateType)))
                    {
                        Error = $"'{root.Subject}' is a {CertificateType} already.";
                        return false;
                    }

                    if (roots.Count >= MaxRoots)
                    {
                        Error = $"There are {MaxRoots} roots already: remove one first.";
                        return false;
                    }

                    roots[(root.Id, root.CertificateType)] = root;
                    Save();

                }

                Root  = root;
                Error = null;
                return true;

            }

        }

        #endregion

        #region TrySetEverywhere(Id, CertificateType, Everywhere)

        /// <summary>
        /// Whether every station is to have the root.
        /// </summary>
        public Boolean TrySetEverywhere(String Id, String CertificateType, Boolean Everywhere)
        {
            lock (updateLock)
            {

                if (!roots.TryGetValue((Id, CertificateType), out var root))
                    return false;

                roots[(Id, CertificateType)] = root with { Everywhere = Everywhere };
                Save();
                return true;

            }
        }

        #endregion

        #region TryRemove(Id, CertificateType)

        /// <summary>
        /// Remove a root from those installed: it stays on the stations that
        /// have it, until it is deleted there.
        /// </summary>
        public Boolean TryRemove(String Id, String CertificateType)
        {
            lock (updateLock)
            {

                if (!roots.Remove((Id, CertificateType)))
                    return false;

                Save();
                return true;

            }
        }

        #endregion


        #region (static) TryRead(PEM, out Certificate, out Error)

        /// <summary>
        /// The one certificate of a PEM, where it is a root: a CA that signed
        /// itself.
        /// </summary>
        public static Boolean TryRead(String                                     PEM,
                                      [NotNullWhen(true)]  out X509Certificate2?  Certificate,
                                      [NotNullWhen(false)] out String?            Error)
        {

            Certificate = null;
            Error       = null;

            var all = new X509Certificate2Collection();

            try
            {
                all.ImportFromPem(PEM);
            }
            catch (CryptographicException e)
            {
                Error = $"That is no certificate in PEM: {e.Message}";
                return false;
            }

            if (all.Count != 1)
            {
                foreach (var one in all) one.Dispose();
                Error = all.Count == 0 ? "That is no certificate in PEM." : "One certificate at a time: that is several.";
                return false;
            }

            var certificate = all[0];

            var isCA        = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority ?? false;
            var selfSigned  = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) && SignedBy(certificate, certificate);

            if (!isCA || !selfSigned)
            {
                Error = $"'{certificate.Subject}' is no root certificate: {(isCA ? "it is not signed by itself" : "it is no CA")}.";
                certificate.Dispose();
                return false;
            }

            Certificate = certificate;
            return true;

        }

        #endregion

        #region (static) RootOf(Certificate, CertificateType, At, Everywhere)

        public static StationRoot RootOf(X509Certificate2  Certificate,
                                         String            CertificateType,
                                         DateTimeOffset    At,
                                         Boolean           Everywhere)

            => new (Certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(),
                    CertificateType,
                    Certificate.ExportCertificatePem() + "\n",
                    Certificate.Subject,
                    Certificate.SerialNumber,
                    Certificate.NotAfter.ToUniversalTime(),
                    At,
                    Everywhere);

        #endregion

        #region (static) HashesOf(PEM, HashAlgorithm)

        /// <summary>
        /// The hashes a station names a root by, as OCPP has them: of its
        /// issuer's name and its issuer's key - its own, a root being its own
        /// issuer - in lower case hexadecimal.
        /// </summary>
        public static (String NameHash, String KeyHash)? HashesOf(String PEM, String HashAlgorithm)
        {

            Func<Byte[], Byte[]>? hash = HashAlgorithm.ToUpperInvariant() switch {
                                             "SHA256"  => SHA256.HashData,
                                             "SHA384"  => SHA384.HashData,
                                             "SHA512"  => SHA512.HashData,
                                             _         => null
                                         };

            if (hash is null)
                return null;

            using var certificate = X509Certificate2.CreateFromPem(PEM);

            return (Convert.ToHexString(hash(certificate.IssuerName.RawData)).ToLowerInvariant(),
                    Convert.ToHexString(hash(certificate.PublicKey.EncodedKeyValue.RawData)).ToLowerInvariant());

        }

        #endregion


        #region (private static) SignedBy(Certificate, Issuer)

        private static Boolean SignedBy(X509Certificate2 Certificate, X509Certificate2 Issuer)
        {

            using var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode     = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode          = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.VerificationFlags  = X509VerificationFlags.IgnoreNotTimeValid;
            chain.ChainPolicy.CustomTrustStore.Add(Issuer);

            return chain.Build(Certificate);

        }

        #endregion

        #region (private) Save()

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
                        new JProperty("roots", new JArray(roots.Values.OrderBy(root => root.CertificateType, StringComparer.Ordinal).
                                                                       ThenBy (root => root.Id,              StringComparer.Ordinal).
                                                                       Select (root => root.ToJSON())))
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
