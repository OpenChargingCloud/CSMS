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
using System.Net;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.CSMS.Configuration
{

    /// <summary>
    /// The "certificateSigning" section of the configuration file: where the
    /// CSR of a charging station's SignCertificate request goes - the EST
    /// server of a PKI, RFC 7030, one for each kind of certificate - and what
    /// this CSMS signs in there with.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "certificateSigning": {
    ///   "chargingStationCertificate": "https://pki.example.org/.well-known/est/stations",
    ///   "v2gCertificate":             "https://pki.example.org/.well-known/est/secc",
    ///   "apiKey":                     "..."
    /// }
    /// </code>
    /// <para>
    /// An address is where EST is, with its label where it has one: the CSR
    /// goes to its "simpleenroll", and the CAs above the certificate come
    /// from its "cacerts". A kind of certificate without one is not signed:
    /// the station is told so. The API key is that of an account of the PKI
    /// that may sign certificates of servers and clients - the "registrar"
    /// role of the PKI - and goes over HTTPS only, or to the loopback address.
    /// </para>
    /// <para>
    /// Null is "the file does not say", as in every section: what is missing
    /// keeps whatever this CSMS had.
    /// </para>
    /// </remarks>
    /// <param name="ChargingStationCertificate">The EST server a charging station's own certificate - its TLS client certificate towards this CSMS - is signed at; null for none.</param>
    /// <param name="V2GCertificate">The EST server a charging station's SECC certificate of ISO 15118-2 is signed at; null for none.</param>
    /// <param name="APIKey">The API key this CSMS signs in to the PKI with; null for none.</param>
    public sealed record CertificateSigningConfiguration(Uri?     ChargingStationCertificate   = null,
                                                         Uri?     V2GCertificate               = null,
                                                         String?  APIKey                       = null)
    {

        #region Data

        /// <summary>
        /// The name of this section in the configuration file.
        /// </summary>
        public const String  SectionName     = "certificateSigning";

        /// <summary>
        /// The longest an API key may be written.
        /// </summary>
        public const Int32   MaxAPIKeyLength = 256;

        #endregion

        #region Properties

        /// <summary>
        /// Whether any kind of certificate is signed at all.
        /// </summary>
        public Boolean Signs
            => ChargingStationCertificate is not null || V2GCertificate is not null;

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The "certificateSigning" section, or the one sentence that says
        /// what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JObject                                                    JSON,
                                       [NotNullWhen(true)]  out CertificateSigningConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?                           Error)
        {

            Configuration  = null;
            Error          = null;

            if (!TryReadAddress(JSON, "chargingStationCertificate", out var chargingStation, out Error) ||
                !TryReadAddress(JSON, "v2gCertificate",             out var v2g,             out Error))
            {
                return false;
            }

            String? apiKey = null;

            if (JSON["apiKey"] is JToken apiKeyToken && apiKeyToken.Type != JTokenType.Null)
            {

                apiKey = apiKeyToken.Type == JTokenType.String ? apiKeyToken.Value<String>()?.Trim() : null;

                if (String.IsNullOrEmpty(apiKey) || apiKey.Length > MaxAPIKeyLength || apiKey.Any(character => Char.IsWhiteSpace(character) || Char.IsControl(character)))
                {
                    Error = $"'{SectionName}.apiKey' is an API key of the PKI: 1 to {MaxAPIKeyLength} characters, none of them a space.";
                    return false;
                }

            }

            Configuration = new CertificateSigningConfiguration(chargingStation, v2g, apiKey);
            return true;

        }

        #endregion

        #region (static) TryReadAddress(JSON, Name, out Address, out Error)

        /// <summary>
        /// The address of an EST server: absolute, http or https - and http
        /// only on the loopback address, where an API key travels nowhere.
        /// </summary>
        private static Boolean TryReadAddress(JObject                           JSON,
                                              String                            Name,
                                              out Uri?                          Address,
                                              [NotNullWhen(false)] out String?  Error)
        {

            Address  = null;
            Error    = null;

            if (JSON[Name] is not JToken token || token.Type == JTokenType.Null)
                return true;

            var text = token.Type == JTokenType.String ? token.Value<String>()?.Trim() : null;

            if (String.IsNullOrEmpty(text) ||
                !Uri.TryCreate(text, UriKind.Absolute, out var address) ||
                address.Scheme is not ("https" or "http") ||
                !String.IsNullOrEmpty(address.Query) ||
                !String.IsNullOrEmpty(address.Fragment))
            {
                Error = $"'{SectionName}.{Name}' is the address of an EST server, as https://pki.example.org/.well-known/est/<label>.";
                return false;
            }

            if (address.Scheme == "http" && !IsLoopback(address))
            {
                Error = $"'{SectionName}.{Name}' is an address of plain HTTP, and the API key of this CSMS - and the certificates of its stations - would travel over it in the clear: " +
                        "HTTPS, or the loopback address.";
                return false;
            }

            Address = new Uri(address.GetLeftPart(UriPartial.Path).TrimEnd('/'));
            return true;

        }

        /// <summary>
        /// Whether an address is on this machine.
        /// </summary>
        public static Boolean IsLoopback(Uri Address)

            => Address.IsLoopback ||
               (IPAddress.TryParse(Address.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip));

        #endregion

        #region Merge(Update)

        /// <summary>
        /// This section with what an update says - where it says anything.
        /// </summary>
        /// <remarks>
        /// An update cannot say "none" with null, which is "it does not say";
        /// see <see cref="Without"/> for that.
        /// </remarks>
        public CertificateSigningConfiguration Merge(CertificateSigningConfiguration Update)

            => new (Update.ChargingStationCertificate ?? ChargingStationCertificate,
                    Update.V2GCertificate             ?? V2GCertificate,
                    Update.APIKey                     ?? APIKey);

        /// <summary>
        /// This section without what the given names of it say: what a JSON
        /// update sets to null.
        /// </summary>
        public CertificateSigningConfiguration Without(IEnumerable<String> Names)
        {

            var names = new HashSet<String>(Names, StringComparer.Ordinal);

            return new (names.Contains("chargingStationCertificate") ? null : ChargingStationCertificate,
                        names.Contains("v2gCertificate")             ? null : V2GCertificate,
                        names.Contains("apiKey")                     ? null : APIKey);

        }

        #endregion

        #region ToJSON(WithAPIKey = true)

        /// <summary>
        /// The section as it is written to the file - and, without its API key,
        /// as the JSON API shows it, with "apiKey" only saying whether there
        /// is one.
        /// </summary>
        public JObject ToJSON(Boolean WithAPIKey = true)
        {

            var json = new JObject();

            if (ChargingStationCertificate is not null)  json.Add("chargingStationCertificate", ChargingStationCertificate.ToString());
            if (V2GCertificate             is not null)  json.Add("v2gCertificate",             V2GCertificate.ToString());

            if (WithAPIKey)
            {
                if (APIKey is not null)
                    json.Add("apiKey", APIKey);
            }
            else
                json.Add("apiKey", APIKey is not null);

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Signs
                   ? String.Join(" and ", new[] {
                                              ChargingStationCertificate is not null ? $"charging station certificates at {ChargingStationCertificate}" : null,
                                              V2GCertificate             is not null ? $"V2G certificates at {V2GCertificate}"                          : null
                                          }.OfType<String>()) +
                     (APIKey is null ? ", signed in with no API key" : "")
                   : "no certificates signed for charging stations";

        #endregion

    }

}
