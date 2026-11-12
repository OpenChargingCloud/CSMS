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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP;
using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Logging;

using OCPPv2_1      = cloud.charging.open.protocols.OCPPv2_1;
using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.Web;

#endregion

namespace cloud.charging.open.CSMS.OCPP
{

    /// <summary>
    /// The key this CSMS signs the pin sets of the charging stations with (white paper "Key Pins and TLS 1.3
    /// Raw Public Keys for Local Controllers", section 5.7, way 1): the CSMS's signing anchor, which a station
    /// is given at commissioning as one of its pin set signers, and by which it believes a pin set that came
    /// through a Local Controller - which can withhold one, but neither forge nor change it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Made on demand, never by itself.</b> A key a station is to believe is one an operator gives it, by
    /// its public key; one made at the first start would be a key nobody wrote down anywhere. And never made
    /// anew over one there is: every station that believes the old one would refuse every pin set signed by a
    /// new one. A file that cannot be read is said, and not replaced either.
    /// </para>
    /// <para>
    /// <b>ECDSA P-256</b>, as the signatures of OCPP messages (EVQI chapter 7), and one purpose only (section
    /// 5.10): not the key of the station server's TLS, not the SSH host key.
    /// </para>
    /// <para>
    /// <b>Beside the configuration file, for its owner alone</b>, as the station server's keys are: the private
    /// key, its public key and when and by whom it was made, in one JSON file. The public key is shown in the
    /// form a station's pin set signers take it: the point of the curve, uncompressed, in base64 - the bytes of
    /// the keyId of a signature.
    /// </para>
    /// </remarks>
    public sealed class PinSetSigningKey
    {

        #region Data

        /// <summary>
        /// The name of the file beside the configuration file.
        /// </summary>
        public const String  DefaultFileName  = "ocpp-pin-set-signing-key.json";

        /// <summary>
        /// Whom a pin set is signed by, as its signature names the signer.
        /// </summary>
        public const String  SignerName       = "CSMS";

        private readonly Object        keyLock  = new ();
        private readonly TimeProvider  timeProvider;

        private ECCKeyPair?            keyPair;
        private DateTimeOffset?        createdAt;
        private String?                createdBy;

        #endregion

        #region Properties

        /// <summary>
        /// Where it is kept.
        /// </summary>
        public String           Path          { get; }

        /// <summary>
        /// Whether there is a key to sign with.
        /// </summary>
        public Boolean          Exists
        {
            get
            {
                lock (keyLock)
                {
                    return keyPair is not null;
                }
            }
        }

        /// <summary>
        /// The public key, as a station's pin set signers take it - the uncompressed point of the curve, in
        /// base64, which is what a signature carries as its keyId - or null where there is no key.
        /// </summary>
        public String?          PublicKey
        {
            get
            {
                lock (keyLock)
                {
                    return keyPair is not null
                               ? Convert.ToBase64String(keyPair.PublicKeyBytes)
                               : null;
                }
            }
        }

        /// <summary>
        /// When it was made.
        /// </summary>
        public DateTimeOffset?  CreatedAt
        {
            get
            {
                lock (keyLock)
                {
                    return createdAt;
                }
            }
        }

        /// <summary>
        /// Who had it made.
        /// </summary>
        public String?          CreatedBy
        {
            get
            {
                lock (keyLock)
                {
                    return createdBy;
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
        /// The signing key in the given file; it need not exist yet.
        /// </summary>
        public PinSetSigningKey(String?        Path           = null,
                                TimeProvider?  TimeProvider   = null)
        {
            this.Path          = System.IO.Path.GetFullPath(Path ?? DefaultFileName);
            this.timeProvider  = TimeProvider ?? TimeProvider.System;
        }

        #endregion


        #region TryLoad(out Error)

        /// <summary>
        /// Read the key, where there is one. No file is no key, and no error; a file that cannot be read, or
        /// whose public key is not the private key's, is an error, and is left where it is.
        /// </summary>
        public Boolean TryLoad([NotNullWhen(false)] out String? Error)
        {

            Error = null;

            lock (keyLock)
            {

                keyPair    = null;
                createdAt  = null;
                createdBy  = null;

                if (!File.Exists(Path))
                    return true;

                try
                {

                    // Closed again where an earlier version - or a copy - left
                    // it open.
                    OwnerOnly.File(Path, problem => OnNotice?.Invoke(LogLevel.Warning, problem));

                    using var reader  = new JsonTextReader(new StringReader(File.ReadAllText(Path))) { DateParseHandling = DateParseHandling.None };

                    var json          = JObject.Load(reader);
                    var privateKey    = json["privateKey"]?.Value<String>();
                    var publicKey     = json["publicKey"]?. Value<String>();

                    if (json["algorithm"]?.Value<String>() is String algorithm && algorithm != "secp256r1")
                    {
                        Error = $"'{Path}' holds a key of '{algorithm}'; pin sets are signed with secp256r1 (P-256).";
                        return false;
                    }

                    if (String.IsNullOrEmpty(privateKey) || String.IsNullOrEmpty(publicKey))
                    {
                        Error = $"'{Path}' holds no key: it has no 'privateKey' or no 'publicKey'.";
                        return false;
                    }

                    var loaded        = new ECCKeyPair(Convert.FromBase64String(publicKey),
                                                       Convert.FromBase64String(privateKey));

                    // The public key written down is what an operator gave the
                    // stations: one that is not the private key's would have
                    // every pin set refused, and nobody would know why.
                    if (loaded.PrivateKey is null ||
                        !loaded.PublicKey.Q.Equals(loaded.PrivateKey.Parameters.G.Multiply(loaded.PrivateKey.D).Normalize()))
                    {
                        Error = $"'{Path}': its public key is not that of its private key.";
                        return false;
                    }

                    keyPair    = loaded;
                    createdAt  = json["createdAt"]?.Type == JTokenType.String &&
                                 DateTimeOffset.TryParse(json["createdAt"]!.Value<String>(), null, System.Globalization.DateTimeStyles.RoundtripKind, out var at)
                                     ? at
                                     : null;
                    createdBy  = json["createdBy"]?.Type == JTokenType.String ? json["createdBy"]!.Value<String>() : null;

                    return true;

                }
                catch (Exception e)
                {
                    Error = $"'{Path}' could not be read: {e.Message}";
                    return false;
                }

            }

        }

        #endregion

        #region TryCreate(CreatedBy, out PublicKey, out Error)

        /// <summary>
        /// Make the key, and write it down for the owner alone - where there is none yet.
        /// </summary>
        /// <param name="CreatedBy">Who had it made, for the record.</param>
        /// <param name="PublicKey">Its public key, as a station's pin set signers take it.</param>
        /// <param name="Error">Why none was made.</param>
        public Boolean TryCreate(String?                           CreatedBy,
                                 [NotNullWhen(true)]  out String?  PublicKey,
                                 [NotNullWhen(false)] out String?  Error)
        {

            PublicKey  = null;
            Error      = null;

            lock (keyLock)
            {

                if (keyPair is not null || File.Exists(Path))
                {
                    Error = $"This CSMS has a signing key for pin sets already, in '{Path}'. It is not made anew: every charging station " +
                             "that believes it would refuse what a new one signs. To start over, take the file away while this CSMS is " +
                             "stopped, and give every station the new key.";
                    return false;
                }

                var made = ECCKeyPair.GenerateKeys();

                if (made is null)
                {
                    Error = "No key of secp256r1 could be made.";
                    return false;
                }

                var now = timeProvider.GetUtcNow();

                try
                {

                    var directory = System.IO.Path.GetDirectoryName(Path);

                    if (!String.IsNullOrEmpty(directory))
                        Directory.CreateDirectory(directory);

                    var temporary = Path + ".tmp";

                    OwnerOnlyFile.Write(
                        temporary,
                        new JObject(
                            new JProperty("algorithm",   "secp256r1"),
                            new JProperty("privateKey",  Convert.ToBase64String(made.PrivateKeyBytes)),
                            new JProperty("publicKey",   Convert.ToBase64String(made.PublicKeyBytes)),
                            new JProperty("createdAt",   now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                            new JProperty("createdBy",   CreatedBy)
                        ).ToString(Formatting.Indented) + Environment.NewLine,
                        problem => OnNotice?.Invoke(LogLevel.Warning, problem)
                    );

                    File.Move(temporary, Path, overwrite: false);

                }
                catch (Exception e)
                {
                    Error = $"The signing key for pin sets could not be written to '{Path}': {e.Message}";
                    return false;
                }

                keyPair    = made;
                createdAt  = now;
                createdBy  = CreatedBy;

                PublicKey  = Convert.ToBase64String(made.PublicKeyBytes);

                return true;

            }

        }

        #endregion

        #region TrySign(Request, out Error)

        /// <summary>
        /// Sign a SetVariables request of a pin set as the station takes it: bound to the CSMS and to OCPP 2.1,
        /// with a nonce in place of the message id - a Local Controller sends the request on under an id of its
        /// own - and named the CSMS's.
        /// </summary>
        /// <remarks>
        /// The signing time is the clock's: a pin set is verified without a time window, its version keeps an
        /// older one from coming back (section 5.7), so a station whose clock was never set takes it all the
        /// same.
        /// </remarks>
        public Boolean TrySign(OCPPv2_1_CSMS.SetVariablesRequest   Request,
                               [NotNullWhen(false)] out String?    Error)
        {

            ECCKeyPair? signer;

            lock (keyLock)
            {
                signer = keyPair;
            }

            if (signer is null)
            {
                Error = "This CSMS has no signing key for pin sets.";
                return false;
            }

            return new SignaturePolicy { NonceInsteadOfMessageId = true }.
                       BindTo(NetworkingNode_Id.CSMS, OCPPv2_1.Version.WebSocketSubProtocolId).
                       SignRequestMessage(Request,
                                          Request.ToJSON(true),
                                          out Error,
                                          signer.ToSignInfo1(SignerName, I18NString.Create("pin set"), timeProvider.GetUtcNow()));

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// What may be shown of it: the public key and when it was made - never the private key.
        /// </summary>
        public JObject ToJSON()
        {

            lock (keyLock)
            {

                return new JObject(
                           new JProperty("exists",     keyPair is not null),
                           new JProperty("algorithm",  keyPair is not null ? "secp256r1" : null),
                           new JProperty("publicKey",  keyPair is not null ? Convert.ToBase64String(keyPair.PublicKeyBytes) : null),
                           new JProperty("createdAt",  createdAt?.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                           new JProperty("createdBy",  createdBy),
                           new JProperty("file",       Path)
                       );

            }

        }

        #endregion

    }

}
