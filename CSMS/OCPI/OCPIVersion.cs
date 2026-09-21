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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Aegir;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.OCPI;

#endregion

namespace cloud.charging.open.CSMS.OCPI
{

    #region RemotePartySpec

    /// <summary>
    /// What it takes to add a roaming partner: who they are, the token they
    /// will use with this operator, and - when this operator is the one that
    /// starts the peering - the token and the versions URL they handed out.
    /// </summary>
    /// <remarks>
    /// Two ways to add one, and they are the two halves of the OCPI
    /// registration. With only <paramref name="OurToken"/> the partner is
    /// expected to come to this CSMS: they GET the versions with that token
    /// and POST their credentials, and the library fills in the rest. With
    /// <paramref name="TheirToken"/> and <paramref name="TheirVersionsURL"/>
    /// as well, this CSMS can go to them - see
    /// <see cref="OCPIVersion.Register"/>.
    /// </remarks>
    /// <param name="CountryCode">The partner's country code.</param>
    /// <param name="PartyId">The partner's party identification.</param>
    /// <param name="Role">What the partner is - an EMSP, almost always.</param>
    /// <param name="Name">Its business name.</param>
    /// <param name="Website">Its website, or null.</param>
    /// <param name="OurToken">The token the partner presents to this CSMS.</param>
    /// <param name="TheirToken">The token this CSMS presents to the partner, or null while they have not handed one out.</param>
    /// <param name="TheirVersionsURL">Where the partner's versions endpoint is, or null.</param>
    public sealed record RemotePartySpec(CountryCode      CountryCode,
                                         Party_Id         PartyId,
                                         Role             Role,
                                         String           Name,
                                         URL?             Website,
                                         AccessToken      OurToken,
                                         AccessToken?     TheirToken,
                                         URL?             TheirVersionsURL)
    {

        /// <summary>
        /// The identification the library files the partner under.
        /// </summary>
        public RemoteParty_Id  Id
            => RemoteParty_Id.From(CountryCode, PartyId, Role);

        /// <summary>
        /// Whether this CSMS has what it needs to start the peering itself.
        /// </summary>
        public Boolean  CanRegister
            => TheirToken.HasValue && TheirVersionsURL.HasValue;

    }

    #endregion

    #region LocationSpec

    /// <summary>
    /// What it takes to publish a charging location: the least every OCPI
    /// version asks for, and nothing that only one of them has.
    /// </summary>
    /// <remarks>
    /// This is the operator's own data, which is the whole difference between
    /// this side of a roaming agreement and the other one: an EMSP's locations
    /// arrived from somebody else and are read-only, where these are written
    /// here and pushed out.
    ///
    /// Deliberately thin. A location in OCPI can carry opening times, images,
    /// an energy mix and a dozen other things, and a CSMS with a field for each
    /// would be an editor for a file format rather than a charge point
    /// operator. What is here is what a partner needs to find the place and
    /// show it on a map.
    /// </remarks>
    /// <param name="Id">The location's identification, e.g. "LOC0001".</param>
    /// <param name="Name">What the place is called.</param>
    /// <param name="Address">Street and number.</param>
    /// <param name="City">The city.</param>
    /// <param name="PostalCode">The postal code.</param>
    /// <param name="Country">The country.</param>
    /// <param name="Coordinates">Where it is.</param>
    /// <param name="TimeZone">The IANA time zone it is in, e.g. "Europe/Berlin".</param>
    /// <param name="Publish">Whether partners may show it to anybody, or only to a driver who is already there.</param>
    public sealed record LocationSpec(Location_Id    Id,
                                      String         Name,
                                      String         Address,
                                      String         City,
                                      String         PostalCode,
                                      Country        Country,
                                      GeoCoordinate  Coordinates,
                                      String         TimeZone,
                                      Boolean        Publish);

    #endregion

    #region RemotePartySummary

    /// <summary>
    /// A roaming partner as the web interface sees it: the same shape for
    /// every OCPI version, and never the whole of what the library keeps.
    /// </summary>
    public sealed record RemotePartySummary(String              Version,
                                            RemoteParty_Id      Id,
                                            CountryCode         CountryCode,
                                            Party_Id            PartyId,
                                            Role                Role,
                                            String              Name,
                                            URL?                Website,
                                            PartyStatus         Status,
                                            AccessToken?        OurToken,
                                            AccessStatus?       OurTokenStatus,
                                            AccessToken?        TheirToken,
                                            URL?                TheirVersionsURL,
                                            RemoteAccessStatus? RemoteStatus,
                                            Version_Id?         SelectedVersion,
                                            DateTimeOffset      Created,
                                            DateTimeOffset      LastUpdated)
    {

        /// <summary>
        /// Whether this CSMS holds what it needs to talk to the partner: a
        /// token of theirs and a place to send it.
        /// </summary>
        public Boolean  CanRegister
            => TheirToken.HasValue && TheirVersionsURL.HasValue;

        /// <summary>
        /// Whether the peering is complete in both directions.
        /// </summary>
        /// <remarks>
        /// A partner that only holds our token may still be on its way, and
        /// one whose token and versions URL were typed in by hand has not been
        /// spoken to yet. What the library writes down once the credentials
        /// have actually been exchanged - in either direction - is the version
        /// the two sides settled on, so that is what says "registered".
        /// </remarks>
        public Boolean  Registered
            => CanRegister && SelectedVersion.HasValue;

        /// <summary>
        /// The partner as the web interface reads it.
        /// </summary>
        /// <param name="IncludeSecrets">Whether the access tokens travel along. They are shown to whoever may manage partners, and to nobody else.</param>
        public JObject ToJSON(Boolean IncludeSecrets)

            => new (
                   new JProperty("version",            Version),
                   new JProperty("id",                 Id.ToString()),
                   new JProperty("countryCode",        CountryCode.ToString()),
                   new JProperty("partyId",            PartyId.ToString()),
                   new JProperty("role",               Role.ToString()),
                   new JProperty("name",               Name),
                   new JProperty("website",            Website?.ToString()),
                   new JProperty("status",             Status.ToString()),
                   new JProperty("ourToken",           IncludeSecrets ? OurToken?.ToString()   : null),
                   new JProperty("hasOurToken",        OurToken.HasValue),
                   new JProperty("ourTokenStatus",     OurTokenStatus?.ToString()),
                   new JProperty("theirToken",         IncludeSecrets ? TheirToken?.ToString() : null),
                   new JProperty("hasTheirToken",      TheirToken.HasValue),
                   new JProperty("theirVersionsURL",   TheirVersionsURL?.ToString()),
                   new JProperty("remoteStatus",       RemoteStatus?.ToString()),
                   new JProperty("selectedVersion",    SelectedVersion?.ToString()),
                   new JProperty("canRegister",        CanRegister),
                   new JProperty("registered",         Registered),
                   new JProperty("created",            Created.    ToString("o")),
                   new JProperty("lastUpdated",        LastUpdated.ToString("o"))
               );

    }

    #endregion

    #region OCPIOperationResult

    /// <summary>
    /// How something that was asked of a roaming partner, or of the store
    /// behind them, went.
    /// </summary>
    /// <param name="Success">Whether it worked.</param>
    /// <param name="Message">What happened, in a sentence the web interface can show.</param>
    /// <param name="Data">Whatever the operation has to hand back, or null.</param>
    public sealed record OCPIOperationResult(Boolean   Success,
                                             String    Message,
                                             JObject?  Data   = null)
    {

        public static OCPIOperationResult Ok    (String Message, JObject? Data = null)
            => new (true,  Message, Data);

        public static OCPIOperationResult Failed(String Message)
            => new (false, Message);

    }

    #endregion


    /// <summary>
    /// One OCPI version this CSMS speaks: the library's Common API and CPO API
    /// for that version, behind one shape the rest of this CSMS can talk to
    /// without knowing which version it is holding.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library keeps a Common API per OCPI version, and each of those has
    /// its own roaming partners, its own locations and its own store of what
    /// the partners sent - the data structures differ between the versions, so
    /// they cannot share one. The web interface, on the other hand, wants one
    /// list of partners and one list of locations. This is where the two meet:
    /// every version answers the same questions, and the CSMS puts the answers
    /// side by side.
    /// </para>
    /// <para>
    /// What comes back is JSON, in the shape the library writes it (the OCPI
    /// shape, with snake_case names), with the version added. A page that
    /// shows a location reads the same fields whichever version it came in
    /// on, which is the point of OCPI having kept them.
    /// </para>
    /// <para>
    /// Which way the data travels is the difference from the EMSP's copy of
    /// this file, and it is the whole difference between the two roles: the
    /// locations, tariffs, sessions and charge detail records here are this
    /// operator's own and it hands them out, and the tokens are the partners'
    /// and arrived by being pushed in.
    /// </para>
    /// </remarks>
    public abstract class OCPIVersion
    {

        #region Properties

        /// <summary>
        /// The CSMS this version belongs to.
        /// </summary>
        public CSMS        CSMS     { get; }

        /// <summary>
        /// The version identification, e.g. "2.2.1".
        /// </summary>
        public abstract Version_Id  Id  { get; }

        /// <summary>
        /// The version as the web interface writes it: "2.2.1".
        /// </summary>
        public String      Label
            => Id.ToString();

        #endregion

        #region Constructor(s)

        protected OCPIVersion(CSMS CSMS)
        {
            this.CSMS = CSMS;
        }

        #endregion


        #region Roaming partners

        /// <summary>
        /// Every roaming partner this version knows.
        /// </summary>
        public abstract IEnumerable<RemotePartySummary>  RemoteParties { get; }

        /// <summary>
        /// One roaming partner, or null.
        /// </summary>
        public RemotePartySummary? GetRemoteParty(RemoteParty_Id Id)
            => RemoteParties.FirstOrDefault(party => party.Id == Id);

        /// <summary>
        /// Add a roaming partner. Answers with what went wrong, or null.
        /// </summary>
        public abstract Task<String?>  AddRemoteParty(RemotePartySpec Spec);

        /// <summary>
        /// Forget a roaming partner: its tokens stop working the moment this
        /// returns.
        /// </summary>
        public abstract Task<Boolean>  RemoveRemoteParty(RemoteParty_Id Id);

        /// <summary>
        /// Start the peering with a partner that handed out its token and its
        /// versions URL: fetch their versions, and POST this operator's
        /// credentials to them.
        /// </summary>
        public abstract Task<OCPIOperationResult>  Register(RemoteParty_Id Id);

        #endregion

        #region What this operator publishes

        /// <summary>
        /// The charging locations of this operator, as the library writes
        /// them.
        /// </summary>
        public abstract IEnumerable<JObject>  Locations  { get; }

        /// <summary>The tariffs of this operator.</summary>
        public abstract IEnumerable<JObject>  Tariffs    { get; }

        /// <summary>The charging sessions of this operator.</summary>
        public abstract IEnumerable<JObject>  Sessions   { get; }

        /// <summary>The charge detail records of this operator.</summary>
        public abstract IEnumerable<JObject>  CDRs       { get; }

        /// <summary>
        /// Whether a location of that identification exists.
        /// </summary>
        public abstract Boolean  HasLocation(Location_Id Id);

        /// <summary>
        /// Publish a location. Answers with what went wrong, or null.
        /// </summary>
        public abstract Task<String?>  AddLocation(LocationSpec Spec);

        /// <summary>
        /// Withdraw a location.
        /// </summary>
        public abstract Task<Boolean>  RemoveLocation(Location_Id Id);

        #endregion

        #region What the partners sent

        /// <summary>
        /// The tokens the roaming partners pushed into this operator: the
        /// cards and app identities their customers charge with.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The mirror image of the EMSP side, where the tokens are its own and
        /// the locations arrived. Here the tokens are somebody else's, which
        /// is why nothing in this CSMS issues one: a token this operator made
        /// up would be a card nobody is billed for.
        /// </para>
        /// <para>
        /// <b>Empty until the library grows somewhere to put them.</b> The OCPI
        /// library files every asset - locations, tariffs, tokens - under one of
        /// the parties its API was built for, and that same list is what the API
        /// answers "who are you" with. Adding the pushing EMSP to it so that its
        /// tokens had somewhere to go would make this operator advertise itself
        /// as an EMSP as well and send EMSP roles in its credentials, so it is
        /// not done. The EMSP side has a store for a partner's assets that is
        /// not a claim about its own identity - EMSP_HTTPAPI.AddRemoteCPO - and
        /// the CPO side has no counterpart yet. A partner's PUT is answered
        /// "the party identification ... is unknown"; see
        /// CSMSTests/OCPITests.APartnerPushesATokenAndItShowsUp.
        /// </para>
        /// </remarks>
        public abstract IEnumerable<JObject>  Tokens     { get; }

        #endregion


        #region EndpointsJSON()

        /// <summary>
        /// Where this version is: its version details, its credentials
        /// endpoint and its CPO modules, as absolute URLs a partner would be
        /// told.
        /// </summary>
        /// <remarks>
        /// Computed here rather than read back from the library, because the
        /// library builds them per request from the Host header, and a page
        /// has no request to hand it. The shape is the library's: the version
        /// details at "versions/2.2.1", the credentials at "v2.2.1/credentials",
        /// the modules at "v2.2.1/cpo/{module}".
        /// </remarks>
        public JObject EndpointsJSON()
        {

            var baseURL  = CSMS.OCPIBaseURL.ToString().TrimEnd('/');
            var prefix   = $"{baseURL}/v{Label}";

            return new JObject(
                       new JProperty("version",       Label),
                       new JProperty("details",       $"{baseURL}/versions/{Label}"),
                       new JProperty("credentials",   $"{prefix}/credentials"),
                       new JProperty("modules",       new JObject(
                           Modules.Select(module => new JProperty(module, $"{prefix}/cpo/{module}"))
                       ))
                   );

        }

        /// <summary>
        /// The CPO modules this version offers, by the name OCPI gives them.
        /// </summary>
        protected abstract IEnumerable<String>  Modules { get; }

        #endregion

        #region (protected) Summarize(...)

        /// <summary>
        /// The parts of a remote party that every version keeps in the same
        /// place, plus the four that each version keeps somewhere else.
        /// </summary>
        protected RemotePartySummary Summarize(RemoteParty      Party,
                                               CountryCode      CountryCode,
                                               Party_Id         PartyId,
                                               Role             Role,
                                               BusinessDetails  BusinessDetails)
        {

            var local   = Party.LocalAccessInfos. FirstOrDefault();
            var remote  = Party.RemoteAccessInfos.FirstOrDefault();

            return new RemotePartySummary(
                       Label,
                       Party.Id,
                       CountryCode,
                       PartyId,
                       Role,
                       BusinessDetails.Name,
                       BusinessDetails.Website,
                       Party.Status,
                       local?. AccessToken,
                       local?. Status,
                       remote?.AccessToken,
                       remote?.VersionsURL,
                       remote?.Status,
                       remote?.SelectedVersionId,
                       Party.Created,
                       Party.LastUpdated
                   );

        }

        #endregion

        #region (protected) WithVersion(JSON, Extra...)

        /// <summary>
        /// An object as the library wrote it, with the version - and whatever
        /// else - put in front.
        /// </summary>
        protected JObject WithVersion(JObject JSON, params JProperty[] Extra)
        {

            var json = new JObject(new JProperty("version", Label));

            foreach (var property in Extra)
                json.Add(property);

            foreach (var property in JSON.Properties())
                json[property.Name] = property.Value;

            return json;

        }

        #endregion

        #region (protected static) DescribeRegistration(...)

        /// <summary>
        /// A registration outcome in one sentence.
        /// </summary>
        protected static OCPIOperationResult DescribeRegistration(RemoteParty_Id  Id,
                                                                  StatusCode?     StatusCode,
                                                                  String?         StatusMessage,
                                                                  Boolean         GotCredentials)
        {

            if (GotCredentials && StatusCode == protocols.OCPI.StatusCode.Success)
                return OCPIOperationResult.Ok($"Registered with '{Id}': they accepted this operator's credentials and handed out theirs.");

            return OCPIOperationResult.Failed(
                       $"The registration with '{Id}' did not go through" +
                       (StatusCode.HasValue ? $" ({StatusCode}" + (StatusMessage.IsNotNullOrEmpty() ? $": {StatusMessage}" : "") + ")" : "") +
                       ". Check their versions URL and the token they handed out; every step is in the log."
                   );

        }

        #endregion

    }

}
