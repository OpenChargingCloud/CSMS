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

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.OCPP.Node.Serving;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// What a CSMS does beside every node that serves charging stations, at
    /// the hooks of <see cref="OCPPServingNode"/>: its charging station server
    /// is that of the serving node, and what is the CSMS's own is hung on it
    /// here.
    /// </summary>
    public partial class CSMS
    {

        #region (private) MoveServerKeysIntoTheStore(Directory)

        /// <summary>
        /// The directory beside the configuration file a CSMS of before kept
        /// the keys and certificates of its charging station port in.
        /// </summary>
        public const String FormerServerKeysDirectoryName = "ocpp-server-keys";

        /// <summary>
        /// Move the keys a CSMS of before kept in a directory of their own into
        /// the certificate store: a key with its certificate is a TLS server
        /// identity there, told the listener "ocpp", and a key whose request is
        /// still out waits there for its certificate.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Once: what was moved is removed where it was, a private key in two
        /// places being one place too many, and the directory with the last
        /// of it. What could not be moved stays, is said in the log, and is
        /// tried again at the next start.
        /// </para>
        /// <para>
        /// A certificate that has run out is moved all the same - it was kept
        /// before, and the station port that shows it says what is wrong with
        /// it better than one that shows nothing.
        /// </para>
        /// <para>
        /// As a local controller moves the keys it dialled its CSMS with - see
        /// its LocalController.Certificates.cs.
        /// </para>
        /// </remarks>
        /// <param name="Directory">Where the keys were kept.</param>
        private void MoveServerKeysIntoTheStore(String Directory)
        {

            if (!System.IO.Directory.Exists(Directory))
                return;

            var moved   = 0;
            var stayed  = 0;

            foreach (var keyFile in System.IO.Directory.GetFiles(Directory, "*.key.pem").Order(StringComparer.Ordinal))
            {

                var name  = System.IO.Path.GetFileName(keyFile);
                var id    = name[..name.IndexOf(".key.pem", StringComparison.Ordinal)];

                String Beside(String Extension)
                    => System.IO.Path.Combine(Directory, $"{id}.{Extension}");

                try
                {

                    var meta       = File.Exists(Beside("json")) ? JObject.Parse(File.ReadAllText(Beside("json"))) : [];

                    var createdAt  = DateTimeOffset.TryParse(meta.Value<String>("createdAt"),
                                                             System.Globalization.CultureInfo.InvariantCulture,
                                                             System.Globalization.DateTimeStyles.RoundtripKind,
                                                             out var parsed)
                                         ? parsed
                                         : new DateTimeOffset(File.GetLastWriteTimeUtc(keyFile));

                    if (!Certificates.TryAdoptRequest(CertificateKind.TLSServerIdentity,
                                                      File.ReadAllText(keyFile),
                                                      File.ReadAllText(Beside("csr.pem")),
                                                      meta.Value<String>("algorithm") ?? CertificateStore.DefaultAlgorithm,
                                                      createdAt,
                                                      [ StationListener ],
                                                      null,
                                                      null,
                                                      out _,
                                                      out var error,
                                                      out _))
                    {
                        stayed++;
                        Log.Warning($"The server key '{id}' in '{Directory}' could not be moved into the certificate store and stays where it is: {error}",
                                    "certificates", "security");
                        continue;
                    }

                    if (File.Exists(Beside("cert.pem")) &&
                        !Certificates.TryAnswerRequest(File.ReadAllText(Beside("cert.pem")), out _, out _, out _, out error, out _, AcceptExpired: true))
                    {
                        stayed++;
                        Log.Warning($"The certificate of the server key '{id}' in '{Directory}' could not be moved into the certificate store and stays where it is, " +
                                    $"with its key: {error}", "certificates", "security");
                        continue;
                    }

                    foreach (var extension in new[] { "cert.pem", "json", "csr.pem", "key.pem" })
                        File.Delete(Beside(extension));

                    moved++;

                }
                catch (Exception e)
                {
                    stayed++;
                    Log.Warning($"The server key '{id}' in '{Directory}' could not be moved into the certificate store and stays where it is: {e.Message}",
                                "certificates", "security");
                }

            }

            if (moved > 0)
                Log.Notice($"{moved} server key(s) of the charging station port moved from '{Directory}' into the certificate store, " +
                           $"as server identities of the listener '{StationListener}'.", "certificates", "ocpp", "tls");

            if (stayed == 0)
            {
                try
                {
                    if (!System.IO.Directory.EnumerateFileSystemEntries(Directory).Any())
                        System.IO.Directory.Delete(Directory);
                }
                catch (Exception e)
                {
                    Log.Debug($"'{Directory}' could not be removed: {e.Message}", "certificates");
                }
            }

        }

        #endregion

        #region (protected override) LetsBackEndsDialIn

        /// <summary>
        /// A CSMS is the back end: nothing above it dials it at the charging
        /// station port. What it dials itself are the nodes below it.
        /// </summary>
        protected override Boolean LetsBackEndsDialIn
            => false;

        #endregion

        #region (protected override) RegistersWithABackEnd

        /// <summary>
        /// A CSMS is the back end: it registers with nobody, and is registered
        /// with.
        /// </summary>
        protected override Boolean RegistersWithABackEnd
            => false;

        #endregion

        #region IsAStation(Node)

        /// <summary>
        /// Whether what registered under the given name is a charging station,
        /// and not a local controller or a gateway - which register with their
        /// BootNotification as well: by the kind its login is marked as, or the
        /// connection this CSMS dials it over.
        /// </summary>
        /// <param name="Node">The name it registered under.</param>
        public Boolean IsAStation(String Node)

            => !WebSocketLogins.SpeaksForOthers(Node) &&
               DialledAs(Node) is not { ConnectionType: cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType.LocalController or
                                                          cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType.Gateway };

        #endregion

        #region (protected override) StationSignedInWithCertificate(StationId, Certificate)

        /// <summary>
        /// What a charging station signed in with is what runs out, and what it
        /// is asked to renew before it does.
        /// </summary>
        protected override void StationSignedInWithCertificate(String            StationId,
                                                               X509Certificate2  Certificate)

            => NotePresentedCertificate(StationId, Certificate);

        #endregion

        #region (protected override) CertificatesChecked()

        /// <summary>
        /// The charging stations' own certificates, which this CSMS can do
        /// something about: the connected ones are asked for new ones.
        /// </summary>
        protected override void CertificatesChecked()

            => _ = Task.Run(() => RenewDueCertificates());

        #endregion

        #region (protected override) OCPPServerStateJSON(State)

        /// <summary>
        /// Beside the state of the charging station server: how many of the
        /// nodes below it this CSMS dials.
        /// </summary>
        protected override void OCPPServerStateJSON(JObject State)

            => State.Add(new JProperty("dialled", DialledNodes.Count));

        #endregion

        #region (protected override) StationLoginRemoved(StationId)

        /// <summary>
        /// A charging station that is gone is not to be asked for new
        /// certificates: what is known of them is forgotten with it.
        /// </summary>
        protected override String StationLoginRemoved(String StationId)
        {

            var forgotten = StationCertificates.Forget(StationId);

            return forgotten > 0
                       ? $", and the {forgotten} certificate(s) known of it"
                       : "";

        }

        #endregion

    }

}
