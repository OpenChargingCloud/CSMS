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
using System.Globalization;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Aegir;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.OCPI;
using cloud.charging.open.protocols.WWCP.Node.Logging;

using cloud.charging.open.CSMS.Configuration;
using cloud.charging.open.CSMS.OCPI;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// The OCPI side of this CSMS: the charge point operator it is, the
    /// endpoints its roaming partners call, the partners themselves, the
    /// locations it publishes, and the tokens the partners pushed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Two protocols, one box.</b> Below this CSMS is OCPP and the charging
    /// stations that dial in; beside it is OCPI and the e-mobility service
    /// providers whose customers charge at those stations. They are separate
    /// all the way down - separate ports, separate identities, separate stores
    /// - and this file is only the second of the two. What ties them together
    /// is that an operator with no stations has nothing to publish and an
    /// operator with no partners has nobody to publish it to.
    /// </para>
    /// <para>
    /// <b>Where the endpoints are.</b> The OCPI library attaches to Hermod's
    /// HTTPExt API rather than to the HTTP server, and it builds the URLs it
    /// advertises - in the versions list and in the version details - from the
    /// Host header and its own path prefix, as if that HTTPExt API sat at the
    /// root of the server. Here it sits at "/ext". So the OCPI endpoints are
    /// registered directly below the HTTPExt API ("/ext/versions",
    /// "/ext/v2.2.1/credentials", "/ext/v2.2.1/cpo/locations"), and the
    /// HTTPExt API's own root path is handed to the library as the prefix it
    /// puts into the URLs it advertises. Both then agree, which is what a
    /// partner that follows the versions list needs.
    /// </para>
    /// <para>
    /// <b>What is per version.</b> The library keeps roaming partners,
    /// locations and the tokens partners push per OCPI version, because the
    /// data structures differ between them. The web interface wants one list
    /// of each, so every version answers the same questions behind
    /// <see cref="OCPIVersion"/> and the answers are put side by side here. A
    /// partner is on exactly one version: the one it was added under, which is
    /// the one it registers on.
    /// </para>
    /// <para>
    /// <b>What is written down.</b> The library keeps its partners and its
    /// assets in append-only files of its own, below an "ocpi" directory
    /// beside the configuration file - one set per version - and reads them
    /// back when it is built. Nothing about OCPI is therefore in
    /// configuration.json but who this operator is and which versions it
    /// offers.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// The directory the OCPI library keeps its files in, below the
        /// directory of the configuration file.
        /// </summary>
        public const String  OCPIDirectoryName  = "ocpi";

        private CommonHTTPAPI            ocpiAPI       = default!;
        private OCPIConfiguration        ocpiSettings  = new ();

        private readonly List<OCPIVersion>  ocpiVersions  = [];

        #endregion

        #region Properties

        /// <summary>
        /// Who this operator is in OCPI, and which versions it offers - as it
        /// was read at the start. Not changeable while running: see
        /// <see cref="OCPIConfiguration"/> for why an identity is a different
        /// kind of setting from an address.
        /// </summary>
        public OCPIConfiguration            OCPI
            => ocpiSettings;

        /// <summary>
        /// The library's Common HTTP API: the versions list every partner
        /// starts from.
        /// </summary>
        public CommonHTTPAPI                OCPIAPI
            => ocpiAPI;

        /// <summary>
        /// The OCPI versions this CSMS speaks, oldest first.
        /// </summary>
        public IReadOnlyList<OCPIVersion>   OCPIVersions
            => ocpiVersions;

        /// <summary>
        /// The country code and party identification of this operator.
        /// </summary>
        public Party_Idv3                   PartyId          { get; private set; }

        /// <summary>
        /// The same, written the way a CPO's is written: "DE*GEF".
        /// </summary>
        /// <remarks>
        /// <see cref="Party_Idv3"/> writes itself without a separator, and
        /// with one only when told which role it is for - a CPO's is written
        /// with an asterisk, an EMSP's with a hyphen. Everything this CSMS
        /// shows about itself uses this form.
        /// </remarks>
        public String                       PartyIdText
            => PartyId.ToString(Role.CPO);

        /// <summary>
        /// The business details of this operator, as its partners see them in
        /// the credentials.
        /// </summary>
        public BusinessDetails              BusinessDetails  { get; private set; } = default!;

        /// <summary>
        /// Where the OCPI endpoints of this CSMS are, from outside: the
        /// HTTPExt API's root on the external address.
        /// </summary>
        public URL                          OCPIBaseURL      { get; private set; }

        /// <summary>
        /// The versions endpoint: the one URL a roaming partner is given.
        /// </summary>
        public URL                          OCPIVersionsURL  { get; private set; }

        /// <summary>
        /// The directory the OCPI library keeps its files in.
        /// </summary>
        public String                       OCPIDirectory    { get; private set; } = default!;

        /// <summary>
        /// How many roaming partners there are, over every version.
        /// </summary>
        public Int32                        RemotePartyCount
            => ocpiVersions.Sum(version => version.RemoteParties.Count());

        /// <summary>
        /// How many locations this operator publishes, over every version.
        /// </summary>
        public Int32                        LocationCount
            => ocpiVersions.Sum(version => version.Locations.Count());

        /// <summary>
        /// How many tokens the partners have pushed, over every version.
        /// </summary>
        public Int32                        TokenCount
            => ocpiVersions.Sum(version => version.Tokens.Count());

        #endregion

        #region (private) BuildOCPI(Configuration)

        /// <summary>
        /// The Common HTTP API and one binding per version offered. Nothing
        /// listens here: the endpoints are on the HTTP server everything else
        /// is on, and it is started by <see cref="Start"/>.
        /// </summary>
        private void BuildOCPI(OCPIConfiguration? Configuration)
        {

            ocpiSettings     = Configuration ?? new OCPIConfiguration();

            #region Who this operator is

            PartyId          = Party_Idv3.From(
                                   CountryCode.Parse(ocpiSettings.CountryCode ?? OCPIConfiguration.DefaultCountryCode),
                                   Party_Id.   Parse(ocpiSettings.PartyId     ?? OCPIConfiguration.DefaultPartyId)
                               );

            BusinessDetails  = new BusinessDetails(
                                   ocpiSettings.Name ?? OCPIConfiguration.DefaultName,
                                   ocpiSettings.Website is { } website && URL.TryParse(website, out var websiteURL)
                                       ? websiteURL
                                       : null
                               );

            #endregion

            #region Where its partners find it

            // The external URL when the operator wrote one down - a CSMS
            // behind a reverse proxy is reached by a name this process has
            // never heard of - and the address this CSMS listens on otherwise.
            var external     = ocpiSettings.ExternalURL
                                   ?? WebInterfaceURL.ToString().TrimEnd('/')[..^BasePathText.Length];

            var extRoot      = ExtAPI.RootPath.ToString().TrimEnd('/');

            OCPIBaseURL      = URL.Parse($"{external}{extRoot}");
            OCPIVersionsURL  = URL.Parse($"{external}{extRoot}/versions");

            // Host and port, which is what the library puts in front of the
            // paths it advertises in the versions list.
            var externalDNSName = new Uri(external).Authority;

            #endregion

            #region Where the library writes

            OCPIDirectory    = Path.Combine(Path.GetDirectoryName(ConfigFile.Path) ?? ".", OCPIDirectoryName);

            #endregion

            #region The Common HTTP API, and the versions on it

            ocpiAPI = new CommonHTTPAPI(

                          HTTPAPI:                   ExtAPI,
                          OurBaseURL:                OCPIBaseURL,
                          OurVersionsURL:            OCPIVersionsURL,

                          Description:               I18NString.Create("The OCPI endpoints of this charge point operator"),

                          // At the HTTPExt API's own root, so that the paths
                          // the library serves and the paths it advertises
                          // are the same thing - see the class remarks.
                          RootPath:                  null,
                          AdditionalURLPathPrefix:   ExtAPI.RootPath,

                          ExternalDNSName:           externalDNSName,
                          HTTPServerName:            $"OpenChargingCloud CSMS v{Version}",
                          HTTPServiceName:           $"OpenChargingCloud CSMS v{Version}",

                          // Whether a location or a tariff of this operator may
                          // be read by anybody who asks, rather than only by a
                          // partner with a token. The operator's decision, and
                          // not a default: a location says where the charging
                          // stations of an estate are.
                          LocationsAsOpenData:       ocpiSettings.LocationsAsOpenData ?? false,
                          TariffsAsOpenData:         ocpiSettings.TariffsAsOpenData   ?? false,
                          AllowDowngrades:           ocpiSettings.AllowDowngrades     ?? false,

                          // The library's own HTTP logging writes files
                          // nobody reads; what happens here goes to the event
                          // log instead. Its databases are unaffected - they
                          // are not logging, whatever the parameter is called.
                          DisableLogging:            true,
                          LoggingPath:               OCPIDirectory

                      );

            foreach (var version in ocpiSettings.EffectiveVersions)
            {

                ocpiVersions.Add(
                    version switch {
                        "2.1.1"  => new OCPIv2_1_1(this, ocpiAPI, OCPIDirectory),
                        "2.2.1"  => new OCPIv2_2_1(this, ocpiAPI, OCPIDirectory),
                        "2.3.0"  => new OCPIv2_3_0(this, ocpiAPI, OCPIDirectory),
                        _        => throw new InvalidOperationException($"'{version}' is not an OCPI version this CSMS speaks.")
                    }
                );

            }

            #endregion

            #region Somebody discovering this operator

            ocpiAPI.OnGetVersionsResponse += (timestamp, api, request, response, cancellationToken) => {

                if (ocpiSettings.Logging?.Requests != false)
                    Log.Info(
                        request.RemoteParty is not null
                            ? $"The roaming partner '{request.RemoteParty.Id}' asked for the OCPI versions."
                            : $"Somebody at {request.HTTPRequest.RemoteSocket} asked for the OCPI versions" +
                              (request.AccessToken.HasValue ? " with a token this operator does not know." : " without a token."),
                        "ocpi", "versions"
                    );

                return Task.CompletedTask;

            };

            #endregion

            Log.Info(
                $"OCPI: this CSMS is the operator {PartyIdText} '{BusinessDetails.Name}', speaking {String.Join(", ", ocpiVersions.Select(version => version.Label))}; " +
                $"its partners find it at {OCPIVersionsURL} and its files are below '{OCPIDirectory}'.",
                "ocpi"
            );

        }

        #endregion

        #region OCPIConfigurationJSON()

        /// <summary>
        /// The OCPI side of this CSMS, as its page in the web interface reads
        /// it: who it is, where it is, and the endpoints of every version.
        /// </summary>
        public JObject OCPIConfigurationJSON()

            => new (

                   new JProperty("party",        new JObject(
                       new JProperty("countryCode",    PartyId.CountryCode.ToString()),
                       new JProperty("partyId",        PartyId.PartyId.    ToString()),
                       new JProperty("id",             PartyIdText),
                       new JProperty("role",           "CPO"),
                       new JProperty("name",           BusinessDetails.Name),
                       new JProperty("website",        BusinessDetails.Website?.ToString())
                   )),

                   new JProperty("endpoints",    new JObject(
                       new JProperty("base",           OCPIBaseURL.    ToString()),
                       new JProperty("versions",       OCPIVersionsURL.ToString()),
                       new JProperty("externalURL",    ocpiSettings.ExternalURL),
                       new JProperty("byVersion",      new JArray(ocpiVersions.Select(version => version.EndpointsJSON())))
                   )),

                   new JProperty("versions",     new JArray(ocpiVersions.Select(version => version.Label))),
                   new JProperty("knownVersions", new JArray(OCPIConfiguration.KnownVersions)),

                   new JProperty("settings",     new JObject(
                       new JProperty("locationsAsOpenData",  ocpiAPI.LocationsAsOpenData),
                       new JProperty("tariffsAsOpenData",    ocpiAPI.TariffsAsOpenData),
                       new JProperty("allowDowngrades",      ocpiAPI.AllowDowngrades ?? false),
                       new JProperty("logRequests",          ocpiSettings.Logging?.Requests != false),
                       new JProperty("logPayloads",          ocpiSettings.Logging?.Payloads == true)
                   )),

                   new JProperty("counts",       new JObject(
                       new JProperty("partners",   RemotePartyCount),
                       new JProperty("locations",  LocationCount),
                       new JProperty("tokens",     TokenCount),
                       new JProperty("tariffs",    ocpiVersions.Sum(version => version.Tariffs. Count())),
                       new JProperty("sessions",   ocpiVersions.Sum(version => version.Sessions.Count())),
                       new JProperty("cdrs",       ocpiVersions.Sum(version => version.CDRs.    Count()))
                   )),

                   new JProperty("directory",    OCPIDirectory),
                   new JProperty("file",         ConfigFile.Path)

               );

        #endregion

        #region TryGetOCPIVersion(Label, out Version)

        /// <summary>
        /// The version written as "2.2.1", or false when this CSMS does not
        /// offer it.
        /// </summary>
        public Boolean TryGetOCPIVersion(String?                                 Label,
                                         [NotNullWhen(true)] out OCPIVersion?    Version)
        {

            Version = ocpiVersions.FirstOrDefault(version => String.Equals(version.Label, Label?.Trim(), StringComparison.OrdinalIgnoreCase));

            return Version is not null;

        }

        #endregion

        #region Roaming partners

        #region RemotePartiesJSON(IncludeSecrets)

        /// <summary>
        /// Every roaming partner, over every version, as the Roaming partners
        /// page reads them.
        /// </summary>
        /// <param name="IncludeSecrets">Whether the access tokens travel along; only to whoever may manage partners.</param>
        public JObject RemotePartiesJSON(Boolean IncludeSecrets)

            => new (
                   new JProperty("partners",   new JArray(
                       ocpiVersions.SelectMany(version => version.RemoteParties).
                                    OrderBy   (party   => party.Id.ToString()).
                                    Select    (party   => party.ToJSON(IncludeSecrets))
                   )),
                   new JProperty("versions",   new JArray(ocpiVersions.Select(version => version.Label))),
                   new JProperty("roles",      new JArray("EMSP", "CPO", "HUB", "NSP", "SCSP", "OTHER")),
                   new JProperty("ourVersionsURL", OCPIVersionsURL.ToString())
               );

        #endregion

        #region AddRemotePartyAsync(JSON)

        /// <summary>
        /// Add a roaming partner, on the version the request names.
        /// </summary>
        /// <remarks>
        /// An empty token of ours means "make one up", and the made-up one
        /// comes back in the result - it is what the operator hands to the
        /// partner, so it has to be shown once. The library keeps it readable,
        /// because it has to compare it on every request; the page shows it
        /// only to whoever may manage partners.
        /// </remarks>
        public async Task<OCPIOperationResult> AddRemotePartyAsync(JObject JSON)
        {

            #region The version

            var label = JSON.Value<String>("version")?.Trim();

            if (String.IsNullOrEmpty(label))
                label = ocpiVersions.LastOrDefault()?.Label;

            if (!TryGetOCPIVersion(label, out var version))
                return OCPIOperationResult.Failed($"'{label}' is not an OCPI version this CSMS offers; there are {String.Join(", ", ocpiVersions.Select(v => v.Label))}.");

            #endregion

            #region Who they are

            if (!CountryCode.TryParse(JSON.Value<String>("countryCode")?.Trim().ToUpperInvariant() ?? "", out var countryCode))
                return OCPIOperationResult.Failed("A 'countryCode' of two letters is required, e.g. \"DE\".");

            if (!Party_Id.TryParse(JSON.Value<String>("partyId")?.Trim().ToUpperInvariant() ?? "", out var partyId))
                return OCPIOperationResult.Failed("A 'partyId' of three letters or digits is required, e.g. \"GDF\".");

            var roleText = JSON.Value<String>("role")?.Trim();

            if (String.IsNullOrEmpty(roleText))
                roleText = "EMSP";

            if (!Role.TryParse(roleText.ToUpperInvariant(), out var role))
                return OCPIOperationResult.Failed($"'{roleText}' is not an OCPI role; there are CPO, EMSP, HUB, NSP, SCSP and OTHER.");

            if (countryCode == PartyId.CountryCode && partyId == PartyId.PartyId && role == Role.CPO)
                return OCPIOperationResult.Failed("That is this operator itself; a CPO cannot be its own roaming partner.");

            var name = JSON.Value<String>("name")?.Trim();

            if (String.IsNullOrEmpty(name))
                return OCPIOperationResult.Failed("A 'name' is required: what the partner calls itself.");

            URL? website = null;

            if (JSON.Value<String>("website")?.Trim() is { Length: > 0 } websiteText)
            {

                if (!URL.TryParse(websiteText, out var websiteURL))
                    return OCPIOperationResult.Failed($"'{websiteText}' is not a URL.");

                website = websiteURL;

            }

            #endregion

            #region The tokens, and where to send ours

            AccessToken ourToken;

            if (JSON.Value<String>("ourToken")?.Trim() is { Length: > 0 } ourTokenText)
            {

                if (!AccessToken.TryParse(ourTokenText, out ourToken))
                    return OCPIOperationResult.Failed("'ourToken' is not a token the OCPI library accepts.");

            }
            else
                ourToken = AccessToken.NewRandom();

            AccessToken?  theirToken        = null;
            URL?          theirVersionsURL  = null;

            var theirTokenText = JSON.Value<String>("theirToken")?.  Trim();
            var theirURLText   = JSON.Value<String>("versionsURL")?. Trim();

            if (!String.IsNullOrEmpty(theirTokenText) || !String.IsNullOrEmpty(theirURLText))
            {

                if (String.IsNullOrEmpty(theirTokenText) || String.IsNullOrEmpty(theirURLText))
                    return OCPIOperationResult.Failed("To start the peering from here both are needed: the partner's token ('theirToken') and its versions URL ('versionsURL'). Leave both empty to let the partner come to this operator.");

                if (!AccessToken.TryParse(theirTokenText, out var parsedTheirToken))
                    return OCPIOperationResult.Failed("'theirToken' is not a token the OCPI library accepts.");

                if (!URL.TryParse(theirURLText, out var parsedURL))
                    return OCPIOperationResult.Failed($"'{theirURLText}' is not a URL.");

                theirToken        = parsedTheirToken;
                theirVersionsURL  = parsedURL;

            }

            #endregion

            var spec = new RemotePartySpec(countryCode, partyId, role, name, website, ourToken, theirToken, theirVersionsURL);

            #region Not twice

            foreach (var other in ocpiVersions)
            {
                if (other.GetRemoteParty(spec.Id) is not null)
                    return OCPIOperationResult.Failed($"There already is a roaming partner '{spec.Id}' on OCPI {other.Label}. Remove it first to add it again.");
            }

            #endregion

            var error = await version.AddRemoteParty(spec);

            if (error is not null)
                return OCPIOperationResult.Failed(error);

            Log.Notice(
                $"The roaming partner '{spec.Id}' ('{name}') was added on OCPI {version.Label}" +
                (spec.CanRegister
                     ? $", with its token and its versions URL {theirVersionsURL}: this operator can start the peering."
                     : ": it is expected to register with the token it was given."),
                "ocpi", "partner"
            );

            var added = version.GetRemoteParty(spec.Id);

            return OCPIOperationResult.Ok(
                       $"The roaming partner '{spec.Id}' was added on OCPI {version.Label}.",
                       new JObject(
                           new JProperty("id",        spec.Id.ToString()),
                           new JProperty("version",   version.Label),
                           new JProperty("ourToken",  ourToken.ToString()),
                           new JProperty("partner",   added?.ToJSON(IncludeSecrets: true))
                       )
                   );

        }

        #endregion

        #region RegisterRemotePartyAsync(Label, Id)

        /// <summary>
        /// Start the peering with a partner: fetch their versions with the
        /// token they handed out, and POST this operator's credentials to them.
        /// </summary>
        public async Task<OCPIOperationResult> RegisterRemotePartyAsync(String? Label, String? Id)
        {

            if (!TryGetOCPIVersion(Label, out var version))
                return OCPIOperationResult.Failed($"'{Label}' is not an OCPI version this CSMS offers.");

            if (!RemoteParty_Id.TryParse(Id, out var remotePartyId))
                return OCPIOperationResult.Failed($"'{Id}' is not a remote party identification; they look like \"DE-GDF_EMSP\".");

            Log.Info($"Starting the OCPI {version.Label} peering with '{remotePartyId}' ...", "ocpi", "credentials", "partner");

            var result = await version.Register(remotePartyId);

            Log.Log(
                result.Success ? LogLevel.Notice : LogLevel.Warning,
                result.Message,
                "ocpi", "credentials", "partner"
            );

            return result;

        }

        #endregion

        #region RemoveRemotePartyAsync(Label, Id)

        /// <summary>
        /// Forget a roaming partner. Its token stops opening this operator the
        /// moment this returns; what it pushed stays, because that is a record
        /// and not a setting.
        /// </summary>
        public async Task<OCPIOperationResult> RemoveRemotePartyAsync(String? Label, String? Id)
        {

            if (!TryGetOCPIVersion(Label, out var version))
                return OCPIOperationResult.Failed($"'{Label}' is not an OCPI version this CSMS offers.");

            if (!RemoteParty_Id.TryParse(Id, out var remotePartyId))
                return OCPIOperationResult.Failed($"'{Id}' is not a remote party identification.");

            if (version.GetRemoteParty(remotePartyId) is null)
                return OCPIOperationResult.Failed($"There is no roaming partner '{remotePartyId}' on OCPI {version.Label}.");

            if (!await version.RemoveRemoteParty(remotePartyId))
                return OCPIOperationResult.Failed($"The roaming partner '{remotePartyId}' could not be removed.");

            Log.Notice($"The roaming partner '{remotePartyId}' was removed from OCPI {version.Label}; its token no longer opens this operator.", "ocpi", "partner");

            return OCPIOperationResult.Ok($"The roaming partner '{remotePartyId}' was removed.");

        }

        #endregion

        #endregion

        #region Locations

        #region LocationsJSON()

        /// <summary>
        /// Every location this operator publishes, over every version, as the
        /// Locations page reads them.
        /// </summary>
        public JObject LocationsJSON()

            => new (
                   new JProperty("locations",  new JArray(ocpiVersions.SelectMany(version => version.Locations))),
                   new JProperty("versions",   new JArray(ocpiVersions.Select(version => version.Label))),
                   new JProperty("operator",   BusinessDetails.Name),
                   new JProperty("partyId",    PartyIdText),
                   new JProperty("openData",   ocpiAPI.LocationsAsOpenData)
               );

        #endregion

        #region AddLocationAsync(JSON)

        /// <summary>
        /// Publish a location, on the version the request names.
        /// </summary>
        /// <remarks>
        /// The other half of what the EMSP does with a token: an operator
        /// writes down where it has charging stations, and the partners fetch
        /// it. What is asked for here is the least OCPI insists on - an
        /// address, a place on the map and a time zone - because a location
        /// that cannot be found is a location a driver is not sent to.
        /// </remarks>
        public async Task<OCPIOperationResult> AddLocationAsync(JObject JSON)
        {

            #region The version

            var label = JSON.Value<String>("version")?.Trim();

            if (String.IsNullOrEmpty(label))
                label = ocpiVersions.LastOrDefault()?.Label;

            if (!TryGetOCPIVersion(label, out var version))
                return OCPIOperationResult.Failed($"'{label}' is not an OCPI version this CSMS offers.");

            #endregion

            #region Where it is

            if (!Location_Id.TryParse(JSON.Value<String>("id")?.Trim() ?? "", out var locationId))
                return OCPIOperationResult.Failed("An 'id' is required: what this operator files the location under, e.g. \"LOC0001\".");

            if (version.HasLocation(locationId))
                return OCPIOperationResult.Failed($"There already is a location '{locationId}' on OCPI {version.Label}. Remove it first to publish it again.");

            var name = JSON.Value<String>("name")?.Trim();

            if (String.IsNullOrEmpty(name))
                return OCPIOperationResult.Failed("A 'name' is required: what the place is called.");

            var address = JSON.Value<String>("address")?.Trim();

            if (String.IsNullOrEmpty(address))
                return OCPIOperationResult.Failed("An 'address' is required: street and number.");

            var city = JSON.Value<String>("city")?.Trim();

            if (String.IsNullOrEmpty(city))
                return OCPIOperationResult.Failed("A 'city' is required.");

            var postalCode = JSON.Value<String>("postalCode")?.Trim();

            if (String.IsNullOrEmpty(postalCode))
                return OCPIOperationResult.Failed("A 'postalCode' is required.");

            var countryText = JSON.Value<String>("country")?.Trim();

            if (String.IsNullOrEmpty(countryText))
                countryText = PartyId.CountryCode.ToString();

            // The three-letter code first, because that is what OCPI asks for;
            // anything else the library recognises - "DE", "Germany" - is taken
            // as well rather than refused over a spelling.
            if (!Country.TryParseAlpha3Code(countryText, out var country) &&
                !Country.TryParse          (countryText, out country))
            {
                return OCPIOperationResult.Failed($"'{countryText}' is not a country; OCPI wants the three-letter code, e.g. \"DEU\".");
            }

            if (JSON["latitude"] is null || JSON["longitude"] is null)
                return OCPIOperationResult.Failed("A 'latitude' and a 'longitude' are required: a location nobody can find is a location nobody is sent to.");

            // Read as numbers rather than asked for as numbers: a browser that
            // sends "50,9" for 50.9 is a comma away from a 500, and the answer
            // should say which field somebody has to look at.
            if (!TryReadNumber(JSON, "latitude",  out var latitude,  out var latitudeError))
                return OCPIOperationResult.Failed(latitudeError);

            if (!TryReadNumber(JSON, "longitude", out var longitude, out var longitudeError))
                return OCPIOperationResult.Failed(longitudeError);

            if (latitude  is < -90  or > 90)
                return OCPIOperationResult.Failed("'latitude' must be between -90 and 90.");

            if (longitude is < -180 or > 180)
                return OCPIOperationResult.Failed("'longitude' must be between -180 and 180.");

            var timeZone = JSON.Value<String>("timeZone")?.Trim();

            if (String.IsNullOrEmpty(timeZone))
                return OCPIOperationResult.Failed("A 'timeZone' is required, e.g. \"Europe/Berlin\": a tariff that changes at night needs to know when night is.");

            #endregion

            var spec = new LocationSpec(
                           locationId,
                           name,
                           address,
                           city,
                           postalCode,
                           country,
                           new GeoCoordinate(Latitude.Parse(latitude), Longitude.Parse(longitude)),
                           timeZone,
                           JSON.Value<Boolean?>("publish") ?? true
                       );

            var error = await version.AddLocation(spec);

            if (error is not null)
                return OCPIOperationResult.Failed(error);

            Log.Notice($"The location '{locationId}' ('{name}', {city}) is published on OCPI {version.Label}.", "ocpi", "locations");

            return OCPIOperationResult.Ok(
                       $"The location '{locationId}' is published on OCPI {version.Label}.",
                       new JObject(
                           new JProperty("id",       locationId.ToString()),
                           new JProperty("version",  version.Label)
                       )
                   );

        }

        #endregion

        #region (private static) TryReadNumber(JSON, Name, out Value, out Error)

        /// <summary>
        /// One number out of a request body, or the sentence that says what
        /// was there instead.
        /// </summary>
        private static Boolean TryReadNumber(JObject                           JSON,
                                             String                            Name,
                                             out Double                        Value,
                                             [NotNullWhen(false)] out String?  Error)
        {

            Value  = 0;
            Error  = null;

            var token = JSON[Name];

            if (token?.Type is JTokenType.Float or JTokenType.Integer)
            {
                Value = token.Value<Double>();
                return true;
            }

            // A string, because a form sends one: taken when it reads as a
            // number in the invariant form, and refused when it does not.
            if (token?.Type == JTokenType.String &&
                Double.TryParse(token.Value<String>(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
            {
                Value = parsed;
                return true;
            }

            Error = $"'{Name}' must be a number, written with a dot.";
            return false;

        }

        #endregion

        #region RemoveLocationAsync(Label, Id)

        /// <summary>
        /// Withdraw a location: the partners stop being shown it.
        /// </summary>
        public async Task<OCPIOperationResult> RemoveLocationAsync(String? Label, String? Id)
        {

            if (!TryGetOCPIVersion(Label, out var version))
                return OCPIOperationResult.Failed($"'{Label}' is not an OCPI version this CSMS offers.");

            if (!Location_Id.TryParse(Id ?? "", out var locationId))
                return OCPIOperationResult.Failed($"'{Id}' is not a location identification.");

            if (!version.HasLocation(locationId))
                return OCPIOperationResult.Failed($"There is no location '{locationId}' on OCPI {version.Label}.");

            if (!await version.RemoveLocation(locationId))
                return OCPIOperationResult.Failed($"The location '{locationId}' could not be withdrawn.");

            Log.Notice($"The location '{locationId}' was withdrawn on OCPI {version.Label}.", "ocpi", "locations");

            return OCPIOperationResult.Ok($"The location '{locationId}' was withdrawn.");

        }

        #endregion

        #endregion

        #region RoamingDataJSON(Kind)

        /// <summary>
        /// One kind of what travels between this operator and its partners,
        /// over every version: the tokens the partners pushed in, and the
        /// tariffs, sessions and charge detail records this operator holds.
        /// </summary>
        public JObject RoamingDataJSON(String Kind)
        {

            var items = Kind switch {
                            "tokens"     => ocpiVersions.SelectMany(version => version.Tokens),
                            "tariffs"    => ocpiVersions.SelectMany(version => version.Tariffs),
                            "sessions"   => ocpiVersions.SelectMany(version => version.Sessions),
                            "cdrs"       => ocpiVersions.SelectMany(version => version.CDRs),
                            _            => throw new ArgumentException($"'{Kind}' is not something that travels between an operator and its partners.", nameof(Kind))
                        };

            return new JObject(
                       new JProperty("kind",      Kind),
                       new JProperty("versions",  new JArray(ocpiVersions.Select(version => version.Label))),
                       new JProperty("items",     new JArray(items))
                   );

        }

        #endregion

    }

}
