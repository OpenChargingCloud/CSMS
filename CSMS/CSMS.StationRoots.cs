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

using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.OCPPv2_1;
using cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.OCPP;

using OCPPCommon = cloud.charging.open.protocols.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// A certificate a charging station says it has, as GetInstalledCertificateIds
    /// names it - and the root of this CSMS it is, where it is one.
    /// </summary>
    public sealed record InstalledCertificate(String   CertificateType,
                                              String   HashAlgorithm,
                                              String   IssuerNameHash,
                                              String   IssuerKeyHash,
                                              String   SerialNumber,
                                              Int32    Children,
                                              String?  Root,
                                              String?  Subject)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("certificateType",  CertificateType),
                   new JProperty("hashAlgorithm",    HashAlgorithm),
                   new JProperty("issuerNameHash",   IssuerNameHash),
                   new JProperty("issuerKeyHash",    IssuerKeyHash),
                   new JProperty("serialNumber",     SerialNumber),
                   new JProperty("children",         Children),
                   new JProperty("root",             Root),
                   new JProperty("subject",          Subject)
               );

    }

    /// <summary>
    /// What a charging station was asked about its certificates, and what it
    /// answered.
    /// </summary>
    /// <param name="Asked">Whether it could be asked at all.</param>
    /// <param name="Answer">What it answered - "Accepted", "Rejected", "Failed", "NotFound" - or, where it could not be asked, "notConnected"; "failed" where the request went wrong.</param>
    /// <param name="Detail">Why, in a sentence, where it is not "Accepted".</param>
    /// <param name="Installed">What it has, where it was asked that.</param>
    public sealed record StationCertificatesAnswer(Boolean                               Asked,
                                                   String                                Answer,
                                                   String?                               Detail     = null,
                                                   IReadOnlyList<InstalledCertificate>?  Installed  = null);

    /// <summary>
    /// A root installed on a station, or a certificate deleted from one.
    /// </summary>
    /// <param name="At">When.</param>
    /// <param name="Station">The charging station.</param>
    /// <param name="Action">"install" or "delete".</param>
    /// <param name="CertificateType">The kind of certificate.</param>
    /// <param name="Certificate">The subject of the root installed; the serial number of the certificate deleted.</param>
    /// <param name="Answer">What the station answered, or why it could not be asked.</param>
    /// <param name="Detail">Why, in a sentence, where it is not "Accepted".</param>
    /// <param name="Automatic">Whether it was installed because every station is to have it, not by hand.</param>
    public sealed record StationRootChange(DateTimeOffset  At,
                                           String          Station,
                                           String          Action,
                                           String          CertificateType,
                                           String          Certificate,
                                           String          Answer,
                                           String?         Detail,
                                           Boolean         Automatic)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("at",               At.ToUniversalTime().ToString("o")),
                   new JProperty("station",          Station),
                   new JProperty("action",           Action),
                   new JProperty("certificateType",  CertificateType),
                   new JProperty("certificate",      Certificate),
                   new JProperty("answer",           Answer),
                   new JProperty("detail",           Detail),
                   new JProperty("automatic",        Automatic)
               );

    }


    /// <summary>
    /// The root certificates of the charging stations: what a station has -
    /// GetInstalledCertificateIds - installed - InstallCertificate - and
    /// deleted - DeleteCertificate - OCPP 2.0.1 and 2.1, M03, M04 and M05.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The roots this CSMS installs are kept beside its configuration file. A
    /// root that every station is to have is installed on a station when it
    /// has been accepted with its BootNotification and does not have it:
    /// the new root of a rollover reaches every station before the first
    /// certificate below it does.
    /// </para>
    /// <para>
    /// The roots may be taken from the PKI: the CAs its EST servers name that
    /// signed themselves - the root above the V2G certificates as the V2G
    /// root, and the root above this CSMS's own TLS certificate as its root.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// How many changes are remembered, the newest first.
        /// </summary>
        public const Int32  StationRootChangesKept  = 100;

        private readonly List<StationRootChange>  stationRootChanges = [];

        #endregion

        #region Properties

        /// <summary>
        /// The root certificates this CSMS installs on its stations.
        /// </summary>
        public StationRoots  StationRoots    { get; private set; } = new ();

        /// <summary>
        /// The roots installed and the certificates deleted, the newest first.
        /// </summary>
        public IReadOnlyList<StationRootChange> StationRootChanges
        {
            get
            {
                lock (stationRootChanges)
                {
                    return [.. Enumerable.Reverse(stationRootChanges)];
                }
            }
        }

        #endregion


        #region (private) BuildStationRoots()

        private void BuildStationRoots()
        {

            StationRoots = new StationRoots(
                               Path.Combine(Path.GetDirectoryName(ConfigFile.Path) ?? ".", StationRoots.DefaultFileName)
                           );

            StationRoots.OnNotice += (level, message) => Log.Log(level, message, "ocpp", "certificate");

            StationRoots.Load();

            csms01.OCPP.OUT.OnBootNotificationResponseSent += (timestamp, sender, connection, request, response, runtime, sentMessageResult, cancellationToken) => {

                if (response.Status == RegistrationStatus.Accepted)
                {
                    var station = request.NetworkPath.Source.ToString();
                    _ = Task.Run(() => InstallRootsEverywhere(station));
                }

                return Task.CompletedTask;

            };

        }

        #endregion


        #region ConnectedStations

        /// <summary>
        /// The charging stations connected now, over a WebSocket or over SSH.
        /// </summary>
        public IReadOnlyList<String> ConnectedStations

            => [.. (ocppWebSocketServer?.WebSocketConnections.Select(StationOn).OfType<String>() ?? []).
                   Concat(ocppOverSSHServed ? (ocppSshServer?.ConnectedNetworkingNodeIds.Select(id => id.ToString()) ?? []) : []).
                   Where(station => station.Length > 0).
                   Distinct().
                   Order(StringComparer.OrdinalIgnoreCase)];

        #endregion

        #region InstalledOn(Station)

        /// <summary>
        /// What certificates a station says it has: GetInstalledCertificateIds,
        /// of every kind.
        /// </summary>
        public async Task<StationCertificatesAnswer> InstalledOn(String Station)
        {

            if (!NetworkingNode_Id.TryParse(Station, out var id) || !IsConnected(Station))
                return new StationCertificatesAnswer(false, NotConnected, $"The charging station '{Station}' is not connected.");

            try
            {

                var response = await csms01.OCPP.OUT.GetInstalledCertificateIds(
                                         new GetInstalledCertificateIdsRequest(SourceRouting.To(id))
                                     );

                var answer   = response.Status.ToString();

                if (answer == "NotFound")
                    return new StationCertificatesAnswer(true, "Accepted", null, []);

                if (answer != "Accepted")
                    return new StationCertificatesAnswer(true, answer, $"'{Station}' answered {answer}{StatusInfoOf(response.StatusInfo)}.");

                var roots    = StationRoots.All;

                return new StationCertificatesAnswer(
                           true,
                           answer,
                           null,
                           [.. response.CertificateHashDataChain.Select(chain => {

                                   var hash   = chain.CertificateHashData;
                                   var root   = roots.FirstOrDefault(root => root.Is(hash.HashAlgorithm.ToString(), hash.IssuerNameHash, hash.IssuerPublicKeyHash, hash.SerialNumber));

                                   return new InstalledCertificate(chain.CertificateType.ToString(),
                                                                   hash.HashAlgorithm.ToString(),
                                                                   hash.IssuerNameHash,
                                                                   hash.IssuerPublicKeyHash,
                                                                   hash.SerialNumber,
                                                                   chain.ChildCertificateHashData.Count(),
                                                                   root?.Id,
                                                                   root?.Subject);

                               })]
                       );

            }
            catch (Exception e)
            {
                return new StationCertificatesAnswer(true, "failed", $"'{Station}' could not be asked: {e.Message}");
            }

        }

        #endregion

        #region InstallRoot(Station, Root, Automatic = false)

        /// <summary>
        /// Install a root on a station: InstallCertificate.
        /// </summary>
        public async Task<StationCertificatesAnswer> InstallRoot(String       Station,
                                                                 StationRoot  Root,
                                                                 Boolean      Automatic = false)
        {

            StationCertificatesAnswer answer;

            if (!NetworkingNode_Id.TryParse(Station, out var id) || !IsConnected(Station))
                answer = new StationCertificatesAnswer(false, NotConnected, $"The charging station '{Station}' is not connected.");

            else
            {
                try
                {

                    var response = await csms01.OCPP.OUT.InstallCertificate(
                                             new InstallCertificateRequest(
                                                 SourceRouting.To(id),
                                                 InstallCertificateUse.Parse(Root.CertificateType),
                                                 OCPPCommon.Certificate.Parse(Root.PEM)
                                             )
                                         );

                    var said     = response.Status.ToString();

                    answer       = new StationCertificatesAnswer(true, said, said == "Accepted" ? null : $"'{Station}' answered {said}{StatusInfoOf(response.StatusInfo)}.");

                }
                catch (Exception e)
                {
                    answer       = new StationCertificatesAnswer(true, "failed", $"'{Station}' could not be asked: {e.Message}");
                }
            }

            Remember(new StationRootChange(TimeProvider.GetUtcNow(), Station, "install", Root.CertificateType, Root.Subject, answer.Answer, answer.Detail, Automatic));

            if (answer.Answer == "Accepted")
                Log.Notice ($"The {Root.CertificateType} '{Root.Subject}' was installed on '{Station}'{(Automatic ? ", as every station is to have it" : "")}.", "ocpp", "certificate", "station");
            else
                Log.Warning($"The {Root.CertificateType} '{Root.Subject}' was not installed on '{Station}': {answer.Detail}", "ocpp", "certificate", "station");

            return answer;

        }

        #endregion

        #region DeleteFrom(Station, CertificateType, HashAlgorithm, IssuerNameHash, IssuerKeyHash, SerialNumber)

        /// <summary>
        /// Delete a certificate from a station: DeleteCertificate.
        /// </summary>
        public async Task<StationCertificatesAnswer> DeleteFrom(String  Station,
                                                                String  CertificateType,
                                                                String  HashAlgorithm,
                                                                String  IssuerNameHash,
                                                                String  IssuerKeyHash,
                                                                String  SerialNumber)
        {

            StationCertificatesAnswer answer;

            if (!NetworkingNode_Id.TryParse(Station, out var id) || !IsConnected(Station))
                answer = new StationCertificatesAnswer(false, NotConnected, $"The charging station '{Station}' is not connected.");

            else
            {
                try
                {

                    var response = await csms01.OCPP.OUT.DeleteCertificate(
                                             new DeleteCertificateRequest(
                                                 SourceRouting.To(id),
                                                 new CertificateHashData(protocols.OCPPv2_1.HashAlgorithm.Parse(HashAlgorithm),
                                                                         IssuerNameHash,
                                                                         IssuerKeyHash,
                                                                         SerialNumber)
                                             )
                                         );

                    var said     = response.Status.ToString();

                    answer       = new StationCertificatesAnswer(true, said, said == "Accepted" ? null : $"'{Station}' answered {said}{StatusInfoOf(response.StatusInfo)}.");

                }
                catch (Exception e)
                {
                    answer       = new StationCertificatesAnswer(true, "failed", $"'{Station}' could not be asked: {e.Message}");
                }
            }

            Remember(new StationRootChange(TimeProvider.GetUtcNow(), Station, "delete", CertificateType, SerialNumber, answer.Answer, answer.Detail, false));

            if (answer.Answer == "Accepted")
                Log.Notice ($"The {CertificateType} {SerialNumber} was deleted from '{Station}'.", "ocpp", "certificate", "station");
            else
                Log.Warning($"The {CertificateType} {SerialNumber} was not deleted from '{Station}': {answer.Detail}", "ocpp", "certificate", "station");

            return answer;

        }

        #endregion

        #region InstallRootsEverywhere(Station)

        /// <summary>
        /// Install on a station every root every station is to have, where it
        /// does not have it.
        /// </summary>
        /// <returns>How many were installed.</returns>
        public async Task<Int32> InstallRootsEverywhere(String Station)
        {

            var everywhere = StationRoots.All.Where(root => root.Everywhere).ToList();

            if (everywhere.Count == 0)
                return 0;

            try
            {

                var installed = await InstalledOn(Station);

                if (installed.Installed is not IReadOnlyList<InstalledCertificate> has)
                {
                    Log.Warning($"What '{Station}' has installed could not be learned, and no root was installed: {installed.Detail}", "ocpp", "certificate", "station");
                    return 0;
                }

                var count = 0;

                foreach (var root in everywhere.Where(root => !has.Any(one => one.Root == root.Id && one.CertificateType == root.CertificateType)))
                    if ((await InstallRoot(Station, root, Automatic: true)).Answer == "Accepted")
                        count++;

                return count;

            }
            catch (Exception e)
            {
                Log.Exception(e, $"The roots of '{Station}' could not be looked at.", "ocpp", "certificate");
                return 0;
            }

        }

        #endregion

        #region RootsFromPKI()

        /// <summary>
        /// The roots the PKI names: the CAs its EST servers hand out that signed
        /// themselves. The root above the V2G certificates is the V2G root; the
        /// one above this CSMS's own TLS certificate is its root.
        /// </summary>
        /// <returns>The roots added, and what could not be asked.</returns>
        public async Task<(IReadOnlyList<StationRoot> Added, IReadOnlyList<String> Problems)> RootsFromPKI()
        {

            var added     = new List<StationRoot>();
            var problems  = new List<String>();
            var found     = new List<(X509Certificate2 Certificate, Boolean V2G)>();

            foreach (var (est, v2g) in new[] { (certificateSigning.ChargingStationCertificate, false), (certificateSigning.V2GCertificate, true) })
            {

                if (est is null)
                    continue;

                try
                {

                    using var http = PKIClient(est);
                    using var cas  = await http.GetAsync($"{est}/cacerts");

                    if (!cas.IsSuccessStatusCode)
                    {
                        problems.Add($"{est}/cacerts answered {(Int32) cas.StatusCode}.");
                        continue;
                    }

                    foreach (var ca in CertificatesOf(await cas.Content.ReadAsStringAsync()))
                    {
                        if (ca.SubjectName.RawData.AsSpan().SequenceEqual(ca.IssuerName.RawData))
                            found.Add((ca, v2g));
                        else
                            ca.Dispose();
                    }

                }
                catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Security.Cryptography.CryptographicException or FormatException)
                {
                    problems.Add($"{est}/cacerts could not be asked: {e.Message}");
                }

            }

            // The root above this CSMS's TLS certificate: the issuer of the
            // last certificate of the chain it serves.
            var served    = ServerCertificates.Select();
            var top       = served?.Intermediates.Cast<X509Certificate2>().LastOrDefault() ?? served?.Certificate;

            foreach (var (certificate, v2g) in found)
            {

                var types = new List<String>();

                if (v2g)
                    types.Add("V2GRootCertificate");

                if (top is not null && certificate.SubjectName.RawData.AsSpan().SequenceEqual(top.IssuerName.RawData))
                    types.Add("CSMSRootCertificate");

                foreach (var type in types)
                    if (StationRoots.Get(certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256).ToLowerInvariant(), type) is null &&
                        StationRoots.TryAdd(certificate.ExportCertificatePem(), type, false, TimeProvider.GetUtcNow(), out var root, out _))
                    {
                        added.Add(root);
                    }

                certificate.Dispose();

            }

            if (added.Count > 0)
                Log.Notice($"Taken from the PKI as roots for the stations: {String.Join(", ", added.Select(root => $"'{root.Subject}' as {root.CertificateType}"))}.", "ocpp", "certificate");

            return (added, problems);

        }

        #endregion


        #region StationRootsJSON()

        /// <summary>
        /// The roots, the connected stations, and the latest changes.
        /// </summary>
        public JObject StationRootsJSON()

            => new (
                   new JProperty("roots",              new JArray(StationRoots.All.Select(root => root.ToJSON()))),
                   new JProperty("certificateTypes",   new JArray(StationRoots.CertificateTypes)),
                   new JProperty("connected",          new JArray(ConnectedStations)),
                   new JProperty("changes",            new JArray(StationRootChanges.Select(change => change.ToJSON())))
               );

        #endregion


        #region (private) Remember(Change)

        private void Remember(StationRootChange Change)
        {
            lock (stationRootChanges)
            {

                stationRootChanges.Add(Change);

                if (stationRootChanges.Count > StationRootChangesKept)
                    stationRootChanges.RemoveRange(0, stationRootChanges.Count - StationRootChangesKept);

            }
        }

        #endregion

        #region (private static) StatusInfoOf(StatusInfo)

        private static String StatusInfoOf(StatusInfo? StatusInfo)

            => StatusInfo is null
                   ? ""
                   : $": {StatusInfo.ReasonCode} {StatusInfo.AdditionalInfo}".TrimEnd();

        #endregion

    }

}
