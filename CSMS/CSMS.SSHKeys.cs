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

using cloud.charging.open.protocols.WWCP.NetworkingNode;

using OCPPv2_1      = cloud.charging.open.protocols.OCPPv2_1;
using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;

#endregion

namespace cloud.charging.open.CSMS
{

    /// <summary>
    /// A charging station's SSH keys, enrolled by the CSMS (white paper "OCPP over SSH", sections 10.2
    /// and 10.3): a SignSSHKey of a station that signs in to this CSMS over SSH puts its next key beside
    /// the current one in the stations' logins; SSHKeySigned then tells the station, and once it took
    /// the key the old ones go. One that comes through a Local Controller is installed there with
    /// InstallSSHKey, and the old ones are deleted there with DeleteSSHKey.
    /// </summary>
    public partial class CSMS
    {

        #region (private) AttachSSHKeyEnrolment(Node)

        private void AttachSSHKeyEnrolment(OCPPv2_1_CSMS.TestCSMSNode Node)
        {

            Node.OCPP.IN.OnSignSSHKey += (timestamp, sender, connection, request, cancellationToken) => {

                if (request.Purpose != OCPPv2_1.SSHKeyPurpose.Station)
                    return Task.FromResult(new OCPPv2_1_CSMS.SignSSHKeyResponse(request, OCPPv2_1.GenericStatus.Rejected,
                                                                                new OCPPv2_1.StatusInfo("NotSupported", "This CSMS enrolls the keys of OCPP only.")));

                var station  = request.NetworkPath.Source;
                var relay    = request.NetworkPath.Length > 1 ? request.NetworkPath.Last : (NetworkingNode_Id?) null;

                // Answered first, enrolled after: SSHKeySigned follows once the key is in.
                _ = Task.Run(() => relay is NetworkingNode_Id localController && localController != station
                                       ? EnrolAtLocalController(Node, station, localController, request.PublicKey)
                                       : EnrolHere(Node, station, request.PublicKey));

                return Task.FromResult(new OCPPv2_1_CSMS.SignSSHKeyResponse(request, OCPPv2_1.GenericStatus.Accepted));

            };

        }

        #endregion

        #region (private) EnrolHere(Node, Station, PublicKey)

        /// <summary>
        /// The next key of a station that signs in to this CSMS: beside the current ones, then told, then
        /// the others taken away.
        /// </summary>
        private async Task EnrolHere(OCPPv2_1_CSMS.TestCSMSNode  Node,
                                     NetworkingNode_Id           Station,
                                     String                      PublicKey)
        {

            var before = StationLogins.Logins.FirstOrDefault(login => login.Id == Station.ToString())?.Keys.Select(key => key.Fingerprint).ToArray() ?? [];

            if (!StationLogins.TryAddSSHKey(Station.ToString(), PublicKey, "Rotated by SignSSHKey", null, null, "OCPP", out var added, out var error))
            {
                Log.Warning($"The next SSH key of the charging station '{Station}' was not enrolled: {error}", "ocpp", "station", "ssh");
                return;
            }

            var signed = await Node.OCPP.OUT.SSHKeySigned(new OCPPv2_1_CSMS.SSHKeySignedRequest(SourceRouting.To(Station), OCPPv2_1.SSHKeyPurpose.Station, PublicKey, NetworkPath: NetworkPath.From(Node.Id)));

            if (signed.Status != OCPPv2_1.GenericStatus.Accepted)
            {
                Log.Warning($"The charging station '{Station}' did not take its next SSH key ({signed.StatusInfo?.ReasonCode ?? signed.Result.ToString()}); its current one stays.",
                            "ocpp", "station", "ssh");
                return;
            }

            foreach (var old in before.Where(fingerprint => fingerprint != added.Fingerprint))
                StationLogins.TryRemoveSSHKey(Station.ToString(), old, out _);

            Log.Notice($"The charging station '{Station}' signs in with its next SSH key {added.Fingerprint} from now on; {before.Length} old one(s) taken away.",
                       "ocpp", "station", "ssh");

        }

        #endregion

        #region (private) EnrolAtLocalController(Node, Station, LocalController, PublicKey)

        /// <summary>
        /// The next key of a station behind a Local Controller: installed there, then told, then the
        /// others deleted there.
        /// </summary>
        private async Task EnrolAtLocalController(OCPPv2_1_CSMS.TestCSMSNode  Node,
                                                  NetworkingNode_Id           Station,
                                                  NetworkingNode_Id           LocalController,
                                                  String                      PublicKey)
        {

            // In the overlay network a request names where it comes from, and one that names nobody is
            // answered to nobody: from this CSMS, as every request of it.
            var to         = SourceRouting.To(LocalController);
            var from       = NetworkPath.From(Node.Id);
            var listed     = await Node.OCPP.OUT.GetInstalledSSHKeys(new OCPPv2_1_CSMS.GetInstalledSSHKeysRequest(to, Station, OCPPv2_1.SSHKeyPurpose.Station,            NetworkPath: from));
            var installed  = await Node.OCPP.OUT.InstallSSHKey      (new OCPPv2_1_CSMS.InstallSSHKeyRequest      (to, Station, OCPPv2_1.SSHKeyPurpose.Station, PublicKey, NetworkPath: from));

            if (installed.Status != OCPPv2_1.GenericStatus.Accepted)
            {
                Log.Warning($"The local controller '{LocalController}' did not install the next SSH key of '{Station}': {installed.StatusInfo?.AdditionalInfo ?? installed.Result.ToString()}",
                            "ocpp", "station", "ssh");
                return;
            }

            var signed = await Node.OCPP.OUT.SSHKeySigned(new OCPPv2_1_CSMS.SSHKeySignedRequest(SourceRouting.To(Station), OCPPv2_1.SSHKeyPurpose.Station, PublicKey, NetworkPath: from));

            if (signed.Status != OCPPv2_1.GenericStatus.Accepted)
                return;

            var next = PublicKey.Split(' ', 3) is [ _, var base64, .. ] ? base64 : PublicKey;

            foreach (var old in listed.Keys.Where(key => !key.PublicKey.Contains(next, StringComparison.Ordinal)))
                await Node.OCPP.OUT.DeleteSSHKey(new OCPPv2_1_CSMS.DeleteSSHKeyRequest(to, Station, old.KeyFingerprint, NetworkPath: from));

            Log.Notice($"The charging station '{Station}' behind '{LocalController}' signs in there with its next SSH key from now on.", "ocpp", "station", "ssh");

        }

        #endregion

    }

}
