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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.OCPPv2_1;
using cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// What came of asking a charging station to renew a certificate.
    /// </summary>
    /// <param name="Asked">Whether the station could be asked at all: it is connected, and the kind of certificate is one this CSMS has signed.</param>
    /// <param name="Answer">What the station answered - "Accepted", "Rejected", "NotImplemented" - or, where it could not be asked, "notConnected" or "notSigned".</param>
    /// <param name="Detail">Why, in a sentence, where it is not "Accepted".</param>
    public sealed record CertificateRenewal(Boolean  Asked,
                                            String   Answer,
                                            String?  Detail = null);


    /// <summary>
    /// The certificates of the charging stations, renewed before they run
    /// out: a station whose certificate - one this CSMS had signed, or one it
    /// signed in with - runs out within the days configured is asked with
    /// TriggerMessage for a SignCertificate of that kind, OCPP 2.0.1 and 2.1,
    /// A02, and the CSR it sends goes the way every other does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>When.</b> When a station has been accepted with its BootNotification
    /// - it is there to be asked, and has just started, as it does after a new
    /// certificate - and every day for the stations that stay connected, with
    /// the other certificates this CSMS looks at. A station is asked once a day
    /// at most for the same certificate: one that says no, or never sends the
    /// CSR, is asked again the next day, not at every reconnection.
    /// </para>
    /// <para>
    /// <b>Only where it can be signed.</b> A kind of certificate this CSMS
    /// sends to no PKI is not asked for: the CSR would be rejected the moment
    /// it arrived.
    /// </para>
    /// <para>
    /// Asked by hand as well - the "Renew now" of the web interface - at once,
    /// whatever is due, for any connected station: a station that signs in
    /// with a password has no certificate to run out, and may be asked for its
    /// first.
    /// </para>
    /// </remarks>
    public partial class CSMS
    {

        #region Data

        /// <summary>
        /// How long a station that was asked to renew a certificate is not
        /// asked again for the same one: a little less than the day between
        /// two checks, so that the next check does ask.
        /// </summary>
        public static TimeSpan  RenewalAskedAgainAfter  { get; } = TimeSpan.FromHours(20);

        /// <summary>
        /// What a renewal asked by hand says where it was not.
        /// </summary>
        public const String  NotConnected  = "notConnected";
        public const String  NotSigned     = "notSigned";

        #endregion

        #region Properties

        /// <summary>
        /// The certificates of the charging stations this CSMS knows of.
        /// </summary>
        public StationCertificates  StationCertificates   { get; private set; } = new ();

        #endregion


        #region (private) BuildCertificateRenewal()

        /// <summary>
        /// The certificates known of, read from beside the configuration file;
        /// and a station accepted with its BootNotification looked at for what
        /// runs out.
        /// </summary>
        private void BuildCertificateRenewal()
        {

            StationCertificates = new StationCertificates(
                                      Path.Combine(Path.GetDirectoryName(ConfigFile.Path) ?? ".", StationCertificates.DefaultFileName)
                                  );

            StationCertificates.OnNotice += (level, message) => Log.Log(level, message, "ocpp", "certificate");

            StationCertificates.Load();

            csms01.OCPP.OUT.OnBootNotificationResponseSent += (timestamp, sender, connection, request, response, runtime, sentMessageResult, cancellationToken) => {

                if (response.Status == RegistrationStatus.Accepted)
                {
                    var station = request.NetworkPath.Source.ToString();
                    _ = Task.Run(() => RenewDueCertificates(station));
                }

                return Task.CompletedTask;

            };

        }

        #endregion

        #region (private) NotePresentedCertificate(Station, Certificate)

        /// <summary>
        /// The certificate a station signed in with, at security profile 3:
        /// its own, and the one it is renewed by.
        /// </summary>
        private void NotePresentedCertificate(String            Station,
                                              X509Certificate2  Certificate)
        {
            try
            {

                StationCertificates.Note(Station,
                                         CertificateSigningUse.ChargingStationCertificate.ToString(),
                                         Certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(),
                                         Certificate.NotAfter.ToUniversalTime(),
                                         "presented",
                                         TimeProvider.GetUtcNow());

            }
            catch (Exception e)
            {
                Log.Exception(e, $"The certificate the charging station '{Station}' signed in with could not be noted.", "ocpp", "certificate");
            }
        }

        #endregion


        #region IsConnected(Station)

        /// <summary>
        /// Whether a charging station can be sent a request now: it is
        /// connected, over a WebSocket or over SSH.
        /// </summary>
        /// <remarks>
        /// Not the routing table of the OCPP node, which keeps a station that
        /// went away as one it has a way to: a request sent there waits for
        /// the answer of nobody until it times out.
        /// </remarks>
        public Boolean IsConnected(String Station)

            => (ocppWebSocketServer?.WebSocketConnections.Any(connection => StationOn(connection) == Station) ?? false) ||
               (ocppOverSSHServed &&
                NetworkingNode_Id.TryParse(Station, out var id) &&
                (ocppSshServer?.ConnectedNetworkingNodeIds.Contains(id) ?? false));

        #endregion

        #region IsDue(Certificate)

        /// <summary>
        /// Whether a certificate runs out within the days it is renewed before.
        /// </summary>
        public Boolean IsDue(StationCertificate Certificate)

            => certificateSigning.RenewBefore > TimeSpan.Zero &&
               Certificate.NotAfter - TimeProvider.GetUtcNow() <= certificateSigning.RenewBefore;

        #endregion

        #region RenewDueCertificates(Station = null)

        /// <summary>
        /// Ask every connected station - or the one given - for a new
        /// certificate where its own runs out soon.
        /// </summary>
        /// <returns>How many were asked.</returns>
        public async Task<Int32> RenewDueCertificates(String? Station = null)
        {

            var asked = 0;

            try
            {

                var now = TimeProvider.GetUtcNow();

                foreach (var certificate in StationCertificates.All)
                {

                    if ((Station is not null && certificate.Station != Station) ||
                        !IsDue(certificate) ||
                        certificateSigning.ESTFor(certificate.CertificateType) is null ||
                        (certificate.RenewalAsked is DateTimeOffset before && now - before < RenewalAskedAgainAfter) ||
                        signingNow.ContainsKey((certificate.Station, certificate.CertificateType)) ||
                        !IsConnected(certificate.Station))
                    {
                        continue;
                    }

                    Log.Info($"The {certificate.CertificateType} of '{certificate.Station}' runs out on {certificate.NotAfter.ToUniversalTime():u}: the station is asked for a new one.",
                             "ocpp", "certificate", "station");

                    await AskToRenew(certificate.Station, certificate.CertificateType);
                    asked++;

                }

            }
            catch (Exception e)
            {
                Log.Exception(e, "The certificates of the charging stations could not be looked at for what runs out.", "ocpp", "certificate");
            }

            return asked;

        }

        #endregion

        #region AskToRenew(Station, CertificateType)

        /// <summary>
        /// Ask a charging station with TriggerMessage for a SignCertificate of
        /// the given kind - now, whatever is due.
        /// </summary>
        public async Task<CertificateRenewal> AskToRenew(String  Station,
                                                         String  CertificateType)
        {

            var trigger = CertificateType switch {
                              "ChargingStationCertificate"  => MessageTrigger.SignChargingStationCertificate,
                              "V2GCertificate"              => MessageTrigger.SignV2GCertificate,
                              _                             => (MessageTrigger?) null
                          };

            if (trigger is null || certificateSigning.ESTFor(CertificateType) is null)
                return new CertificateRenewal(false, NotSigned, $"This CSMS signs no {CertificateType}: it was told no PKI to send it to.");

            if (!NetworkingNode_Id.TryParse(Station, out var id) || !IsConnected(Station))
                return new CertificateRenewal(false, NotConnected, $"The charging station '{Station}' is not connected.");

            var now      = TimeProvider.GetUtcNow();
            CertificateRenewal renewal;

            try
            {

                var response = await csms01.OCPP.OUT.TriggerMessage(
                                         new TriggerMessageRequest(
                                             SourceRouting.To(id),
                                             trigger.Value
                                         )
                                     );

                var answer   = response.Status.ToString();

                renewal      = new CertificateRenewal(true,
                                                      answer,
                                                      answer == "Accepted"
                                                          ? null
                                                          : $"'{Station}' answered {answer}{(response.StatusInfo is null ? "" : $": {response.StatusInfo.ReasonCode} {response.StatusInfo.AdditionalInfo}".TrimEnd())}.");

            }
            catch (Exception e)
            {
                renewal      = new CertificateRenewal(true, "failed", $"'{Station}' could not be asked: {e.Message}");
            }

            StationCertificates.NoteAsked(Station, CertificateType, now, renewal.Answer);

            if (renewal.Answer == "Accepted")
                Log.Info   ($"'{Station}' was asked for a new {CertificateType}, and is about to send its CSR.", "ocpp", "certificate", "station");
            else
                Log.Warning($"'{Station}' was asked for a new {CertificateType}: {renewal.Detail}", "ocpp", "certificate", "station");

            return renewal;

        }

        #endregion

    }

}
