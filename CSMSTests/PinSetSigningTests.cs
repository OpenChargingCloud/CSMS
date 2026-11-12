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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.protocols.WWCP;
using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using OCPPv2_1      = cloud.charging.open.protocols.OCPPv2_1;
using OCPPv2_1_CSMS = cloud.charging.open.protocols.OCPPv2_1.CSMS;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// What a station checks of a pin set, done as the station does it: the signature of the CSMS's key, whose
    /// public key it was given at commissioning, for the station as its CSMS knows it.
    /// </summary>
    internal static class AsTheStationChecks
    {

        /// <summary>
        /// The request as a station reads it off the wire: parsed from the JSON it was sent as.
        /// </summary>
        public static OCPPv2_1_CSMS.SetVariablesRequest Received(JObject  Payload,
                                                                 String   RequestId,
                                                                 String   Destination)
        {

            Assert.That(OCPPv2_1_CSMS.SetVariablesRequest.TryParse(Payload,
                                                                   Request_Id.Parse(RequestId),
                                                                   SourceRouting.To(NetworkingNode_Id.Parse(Destination)),
                                                                   NetworkPath.From(NetworkingNode_Id.Parse("csms001")),
                                                                   out var request,
                                                                   out var error),
                        Is.True, error);

            return request!;

        }

        /// <summary>
        /// Whether the given signer signed the request for the given station, as ChargingStation's
        /// SignedByPinSetSigner verifies it: a rule of the request's context that verifies any of its
        /// signatures by that key, bound to the station's identity and OCPP 2.1 - without the time window, for
        /// a pin set, or with it, by the given clock.
        /// </summary>
        public static Boolean Verifies(OCPPv2_1_CSMS.SetVariablesRequest   Request,
                                       String                              SignerPublicKey,
                                       String                              Identity,
                                       Boolean                             WithoutTimeWindow,
                                       out String?                         Error,
                                       DateTimeOffset?                     Now   = null)
        {

            var policy = new SignaturePolicy(VerificationRules: [ new VerificationRule(Request.Context,
                                                                                       0,
                                                                                       VerificationRuleActions.VerifyAny,
                                                                                       new KeyPair(Convert.FromBase64String(SignerPublicKey)),
                                                                                       WithoutTimeWindow: WithoutTimeWindow) ]) {
                             Now = () => Now ?? DateTimeOffset.UtcNow
                         }.BindTo(NetworkingNode_Id.Parse(Identity), OCPPv2_1.Version.WebSocketSubProtocolId);

            return policy.VerifyRequestMessage(Request, Request.ToJSON(true), out Error);

        }

    }


    /// <summary>
    /// The key the pin sets are signed with (white paper "Key Pins and TLS 1.3 Raw Public Keys for Local
    /// Controllers", section 5.7, way 1), the pin set it signs, and how the endpoint it is for is chosen from a
    /// station's report.
    /// </summary>
    public class PinSetSigningTests
    {

        #region Data

        private String     directory  = default!;
        private TestClock  clock      = default!;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeAnOpenDirectory()
        {
            directory = TestCSMSs.TemporaryDirectory("pin-set-signer");
            clock     = TestClock.At(2026, 11, 12);
            Directory.CreateDirectory(directory);
            OwnerOnlyChecks.OpenToEverybody(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
        {
            TestCSMSs.Remove(directory);
        }

        #endregion


        #region (private) Helpers

        private String KeyFile
            => Path.Combine(directory, PinSetSigningKey.DefaultFileName);

        private PinSetSigningKey ASigner()
        {

            var signer = new PinSetSigningKey(KeyFile, clock);

            Assert.That(signer.TryCreate("admin", out _, out var error), Is.True, error);

            return signer;

        }

        private static KeyPin APin()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return KeyPin.FromKey(key);
        }

        /// <summary>
        /// A pin set, signed by the given signer, as the station receives it.
        /// </summary>
        /// <remarks>
        /// Delivered to the station it was signed for, unless another is given: a local controller can send a
        /// request to whichever station it likes, the frame's destination being no part of what is signed.
        /// </remarks>
        private static OCPPv2_1_CSMS.SetVariablesRequest ASignedPinSet(PinSetSigningKey  Signer,
                                                                        String            Station       = "cs001",
                                                                        UInt64            Version       = 4,
                                                                        String?           DeliveredTo   = null,
                                                                        params KeyPin[]   Pins)
        {

            var request = CSMS.PinSetRequest(NetworkingNode_Id.Parse(Station), "csms-lc", Pins.Length > 0 ? Pins : [ APin() ], Version);

            Assert.That(Signer.TrySign(request, out var error), Is.True, error);

            // Sent under another message id than it was made with, as the
            // local controller sends it on.
            return AsTheStationChecks.Received(request.ToJSON(false), Guid.NewGuid().ToString(), DeliveredTo ?? Station);

        }

        #endregion


        #region ASigningKey_IsMadeOnDemand_ForTheOwnerAlone_AndReadBack()

        /// <summary>
        /// No key until one is made; made, it is written for its owner alone - in a directory everybody may
        /// read - with who made it, and read back as the same key.
        /// </summary>
        [Test]
        public void ASigningKey_IsMadeOnDemand_ForTheOwnerAlone_AndReadBack()
        {

            var signer = new PinSetSigningKey(KeyFile, clock);

            Assert.Multiple(() => {
                Assert.That(signer.TryLoad(out var loadError),  Is.True, loadError);
                Assert.That(signer.Exists,                      Is.False, "a key was there before one was made");
                Assert.That(File.Exists(KeyFile),               Is.False, "reading made a key");
            });

            Assert.That(signer.TryCreate("admin", out var publicKey, out var error), Is.True, error);

            // Before it is read again, which closes a key left open.
            var othersMayRead  = OwnerOnlyChecks.OthersMayGetIn(KeyFile).ToArray();

            var again          = new PinSetSigningKey(KeyFile, clock);

            Assert.That(again.TryLoad(out var reloadError), Is.True, reloadError);

            Assert.Multiple(() => {
                Assert.That(othersMayRead,                            Is.Empty, "others may read the signing key");
                Assert.That(again.Exists,                             Is.True);
                Assert.That(again.PublicKey,                          Is.EqualTo(publicKey), "read back as another key");
                Assert.That(again.CreatedBy,                          Is.EqualTo("admin"));
                Assert.That(again.CreatedAt,                          Is.EqualTo(clock.Now).Within(TimeSpan.FromSeconds(1)));
                Assert.That(again.ToJSON().ToString(),                Does.Not.Contain(JObject.Parse(File.ReadAllText(KeyFile))["privateKey"]!.Value<String>()!),
                                                                      "what is shown of the key holds its private key");
            });

        }

        #endregion

        #region ASigningKeyLeftOpen_IsClosedWhenItIsRead()

        /// <summary>
        /// A key file an earlier version, or a copy, left open to others is closed when it is read at the start.
        /// </summary>
        [Test]
        public void ASigningKeyLeftOpen_IsClosedWhenItIsRead()
        {

            ASigner();

            OwnerOnlyChecks.OpenToEverybody(KeyFile);

            Assert.That(OwnerOnlyChecks.OthersMayGetIn(KeyFile), Is.Not.Empty, "the test's key file is not open to begin with");

            Assert.That(new PinSetSigningKey(KeyFile, clock).TryLoad(out var error), Is.True, error);

            Assert.That(OwnerOnlyChecks.OthersMayGetIn(KeyFile), Is.Empty, "others may still read the signing key");

        }

        #endregion

        #region ThePublicKey_IsInTheFormOfAStationsPinSetSigners()

        /// <summary>
        /// The public key is shown as a station's pin set signers take it: the uncompressed point of P-256 in
        /// base64 - the very bytes of the keyId of the signatures it makes.
        /// </summary>
        [Test]
        public void ThePublicKey_IsInTheFormOfAStationsPinSetSigners()
        {

            var signer   = ASigner();
            var bytes    = Convert.FromBase64String(signer.PublicKey!);
            var request  = ASignedPinSet(signer);

            Assert.Multiple(() => {
                Assert.That(bytes,                                     Has.Length.EqualTo(65), "not an uncompressed point of P-256");
                Assert.That(bytes[0],                                  Is.EqualTo(4));
                Assert.That(request.Signatures.Single().KeyId,         Is.EqualTo(bytes), "the signature names another key than the one shown");
            });

        }

        #endregion

        #region ASignedPinSet_IsVerifiedAsTheStationVerifiesIt()

        /// <summary>
        /// A pin set signed by the key is verified as the station verifies one: by the public key shown, for the
        /// station it is addressed to, without the time window - so a station whose clock was never set takes
        /// it, signed long ago or far in its future. With the time window, a signature of years ago is refused:
        /// the window is left out on purpose.
        /// </summary>
        [Test]
        public void ASignedPinSet_IsVerifiedAsTheStationVerifiesIt()
        {

            var signer   = ASigner();
            var request  = ASignedPinSet(signer);

            var now          = AsTheStationChecks.Verifies(request, signer.PublicKey!, "cs001", WithoutTimeWindow: true, out var nowError);
            var unsetClock   = AsTheStationChecks.Verifies(ASignedPinSet(signer), signer.PublicKey!, "cs001", WithoutTimeWindow: true, out var unsetError, Now: new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero));
            var withWindow   = AsTheStationChecks.Verifies(ASignedPinSet(signer), signer.PublicKey!, "cs001", WithoutTimeWindow: false, out _, Now: clock.Now.AddYears(3));

            Assert.Multiple(() => {
                Assert.That(now,         Is.True,  nowError);
                Assert.That(unsetClock,  Is.True,  $"a station whose clock was never set refuses it: {unsetError}");
                Assert.That(withWindow,  Is.False, "the time window was not what let it through above");
            });

        }

        #endregion

        #region APinSetSignedForAnotherStation_OrByAnotherKey_IsRefused()

        /// <summary>
        /// The signature binds the station it is for, and is the CSMS's key's: a station refuses a pin set
        /// signed for another, and one checked against another key than the one it was given.
        /// </summary>
        [Test]
        public void APinSetSignedForAnotherStation_OrByAnotherKey_IsRefused()
        {

            var signer    = ASigner();
            var other     = new PinSetSigningKey(Path.Combine(directory, "other.json"), clock);

            Assert.That(other.TryCreate(null, out _, out var otherError), Is.True, otherError);

            var forCS002  = ASignedPinSet(signer, Station: "cs002", DeliveredTo: "cs001");

            var asCS001   = AsTheStationChecks.Verifies(forCS002,              signer.PublicKey!, "cs001", WithoutTimeWindow: true, out var asCS001Error);
            var byOther   = AsTheStationChecks.Verifies(ASignedPinSet(signer),  other.PublicKey!,  "cs001", WithoutTimeWindow: true, out var byOtherError);

            Assert.Multiple(() => {
                Assert.That(asCS001,  Is.False, "a pin set signed for cs002 was taken by cs001");
                Assert.That(byOther,  Is.False, "a pin set was taken by a key that did not sign it");
            });

        }

        #endregion

        #region ThePinSet_IsTwoEntries_WithANonceInPlaceOfTheMessageId()

        /// <summary>
        /// A pin set is one SetVariables with two entries of the endpoint's TLSClientController instance:
        /// ServerKeyPins, the pins comma separated in hexadecimal, and ServerKeyPinsVersion; its signature is
        /// the CSMS's, with "*" and a nonce in place of the message id, which the local controller replaces.
        /// </summary>
        [Test]
        public void ThePinSet_IsTwoEntries_WithANonceInPlaceOfTheMessageId()
        {

            var signer   = ASigner();
            var current  = APin();
            var next     = APin();

            var request  = ASignedPinSet(signer, "cs001", 7, null, current, next);
            var entries  = request.VariableData.ToArray();
            var header   = request.Signatures.Single().ProtectedHeader!;

            Assert.Multiple(() => {

                Assert.That(entries,                                           Has.Length.EqualTo(2));
                Assert.That(entries.Select(entry => entry.Component.Name),     Is.All.EqualTo("TLSClientController"));
                Assert.That(entries.Select(entry => entry.Component.Instance), Is.All.EqualTo("csms-lc"));
                Assert.That(entries[0].Variable.Name,                          Is.EqualTo("ServerKeyPins"));
                Assert.That(entries[0].AttributeValue,                         Is.EqualTo($"{current.ToHex()},{next.ToHex()}"));
                Assert.That(entries[1].Variable.Name,                          Is.EqualTo("ServerKeyPinsVersion"));
                Assert.That(entries[1].AttributeValue,                         Is.EqualTo("7"));

                Assert.That(header["OCPPMessageId"]?.Value<String>(),          Is.EqualTo("*"));
                Assert.That(header["OCPPNonce"]?.Value<String>(),              Is.Not.Null.And.Not.Empty);
                Assert.That(header["OCPPDestination"]?.Value<String>(),        Is.EqualTo("cs001"));
                Assert.That(header["OCPPSource"]?.Value<String>(),             Is.EqualTo("CSMS"));
                Assert.That(header["OCPPAction"]?.Value<String>(),             Is.EqualTo("SetVariables"));
                Assert.That(header["OCPPSignerName"]?.Value<String>(),         Is.EqualTo("CSMS"));

            });

        }

        #endregion

        #region ASecondKey_IsNotMade_AndAnUnreadableOne_IsNotReplaced()

        /// <summary>
        /// The key the stations believe is never made anew: not over one there is, and not over a file that
        /// cannot be read - which is said, and left as it was.
        /// </summary>
        [Test]
        public void ASecondKey_IsNotMade_AndAnUnreadableOne_IsNotReplaced()
        {

            var signer   = ASigner();
            var first    = File.ReadAllText(KeyFile);

            var second   = signer.TryCreate("admin", out _, out var secondError);

            Assert.Multiple(() => {
                Assert.That(second,                   Is.False, "a second key was made over the first");
                Assert.That(secondError,              Does.Contain("not made anew"));
                Assert.That(File.ReadAllText(KeyFile), Is.EqualTo(first));
            });

            File.WriteAllText(KeyFile, "{ not json");

            var broken   = new PinSetSigningKey(KeyFile, clock);
            var loaded   = broken.TryLoad(out var loadError);
            var made     = broken.TryCreate("admin", out _, out _);

            Assert.Multiple(() => {
                Assert.That(loaded,                    Is.False, "an unreadable key was read");
                Assert.That(loadError,                 Does.Contain(KeyFile));
                Assert.That(broken.Exists,             Is.False);
                Assert.That(made,                      Is.False, "an unreadable key was replaced");
                Assert.That(File.ReadAllText(KeyFile),  Is.EqualTo("{ not json"));
            });

        }

        #endregion

        #region APublicKeyThatIsNotThePrivateKeys_IsRefused()

        /// <summary>
        /// The public key written down is what the stations were given: one that is not the private key's is
        /// refused when read, and nothing is signed with it.
        /// </summary>
        [Test]
        public void APublicKeyThatIsNotThePrivateKeys_IsRefused()
        {

            ASigner();

            var other  = ECCKeyPair.GenerateKeys()!;
            var json   = JObject.Parse(File.ReadAllText(KeyFile));

            json["publicKey"] = Convert.ToBase64String(other.PublicKeyBytes);

            File.WriteAllText(KeyFile, json.ToString());

            var signer  = new PinSetSigningKey(KeyFile, clock);
            var loaded  = signer.TryLoad(out var error);
            var signed  = signer.TrySign(CSMS.PinSetRequest(NetworkingNode_Id.Parse("cs001"), "csms-lc", [ APin() ], 1), out _);

            Assert.Multiple(() => {
                Assert.That(loaded,  Is.False, "a public key that is not the private key's was taken");
                Assert.That(error,   Does.Contain("not that of its private key"));
                Assert.That(signed,  Is.False, "a pin set was signed without a key");
            });

        }

        #endregion


        #region (private) Endpoint(...)

        private static StationEndpoint Endpoint(String     Connection,
                                                KeyPin?    Learned  = null,
                                                KeyPin?    Shown    = null,
                                                KeyPin[]?  Pins     = null)

            => new (Connection, $"wss://somewhere/{Connection}", Pins ?? [], 0, Learned is not null ? "Learned" : "Configured", Learned, Shown);

        #endregion

        #region TheEndpoint_IsTheOneThatLeadsToTheController()

        /// <summary>
        /// Of a station's endpoints the pins go to the one that leads to its controller: the one it named in its
        /// KeyPinLearned; else the one that learned, was shown or holds one of the controller's pins - in that
        /// order; else the one pins were handed before; else the only one on probation, or the only one at all.
        /// None where none can be told.
        /// </summary>
        [Test]
        public void TheEndpoint_IsTheOneThatLeadsToTheController()
        {

            var current     = APin();
            var next        = APin();
            var stranger    = APin();
            var pins        = new[] { current, next };

            var direct      = Endpoint("csms",   Shown:   stranger, Pins: [ stranger ]);
            var learning    = Endpoint("lc",     Learned: current);
            var shown       = Endpoint("lc",     Shown:   next);
            var holding     = Endpoint("lc",     Pins:    [ current ]);
            var impostor    = Endpoint("lc",     Learned: stranger);
            var elsewhere   = Endpoint("other",  Learned: stranger);
            var other       = Endpoint("other");

            // Each case is one that the rule it names alone decides: without
            // that rule, another endpoint, or none, would be chosen.
            Assert.Multiple(() => {

                Assert.That(CSMS.ChooseEndpoint([ elsewhere, learning ], pins, null,     null)?.Connection,     Is.EqualTo("lc"),     "the one that learned the controller's pin");
                Assert.That(CSMS.ChooseEndpoint([ direct,    shown    ], pins, null,     null)?.Connection,     Is.EqualTo("lc"),     "the one that was shown the controller's key");
                Assert.That(CSMS.ChooseEndpoint([ direct,    holding  ], pins, null,     null)?.Connection,     Is.EqualTo("lc"),     "the one that holds the controller's pin");
                Assert.That(CSMS.ChooseEndpoint([ learning,  other    ], pins, "other",  null)?.Connection,     Is.EqualTo("other"),  "the one the station named");
                Assert.That(CSMS.ChooseEndpoint([ direct,    impostor ], pins, null,     null)?.Connection,     Is.EqualTo("lc"),     "the only one on probation");
                Assert.That(CSMS.ChooseEndpoint([ direct,    other    ], pins, null,     "other")?.Connection,  Is.EqualTo("other"),  "the one pins were handed before");
                Assert.That(CSMS.ChooseEndpoint([ other               ], pins, null,     null)?.Connection,     Is.EqualTo("other"),  "the only one");

                Assert.That(CSMS.ChooseEndpoint([ direct, other    ], pins, null,    null),              Is.Null,              "one was guessed among endpoints none of which leads to the controller");
                Assert.That(CSMS.ChooseEndpoint([ direct, other    ], pins, "gone",  null),              Is.Null,              "an endpoint the station named and does not have was guessed at");
                Assert.That(CSMS.ChooseEndpoint([],                   pins, null,    null),              Is.Null);

            });

        }

        #endregion

        #region AReport_IsReadIntoEndpoints()

        /// <summary>
        /// A station's report of TLSClientController is read into its endpoints: each instance with a name, its
        /// pins, version, state, learned and shown key pin and URL; the instance without a name - the station's
        /// own key - and other components are no endpoint.
        /// </summary>
        [Test]
        public void AReport_IsReadIntoEndpoints()
        {

            var current = APin();
            var next    = APin();

            static OCPPv2_1.ReportData Data(String Component, String? Instance, String Variable, String Value)

                => new (new OCPPv2_1.Component(Component, Instance),
                        new OCPPv2_1.Variable(Variable),
                        [ new OCPPv2_1.VariableAttribute(OCPPv2_1.AttributeTypes.Actual, Value) ]);

            var endpoints = CSMS.EndpointsIn([
                                Data("TLSClientController", "lc",   "ServerKeyPins",         $"{current.ToHex()}, {next.ToHexWithColons()}"),
                                Data("TLSClientController", "lc",   "ServerKeyPinsVersion",  "12"),
                                Data("TLSClientController", "lc",   "ServerKeyPinState",     "Confirmed"),
                                Data("TLSClientController", "lc",   "LearnedKeyPin",         ""),
                                Data("TLSClientController", "lc",   "KeyPinShown",           current.ToHex()),
                                Data("TLSClientController", "lc",   "URL",                   "wss://lc001/cs001"),
                                Data("TLSClientController", "csms", "ServerKeyPins",         ""),
                                Data("TLSClientController", null,   "ClientKeyPin",          current.ToHex()),
                                Data("SSHClientController", "lc",   "HostKey",               "whatever")
                            ]);

            var lc = endpoints.SingleOrDefault(endpoint => endpoint.Connection == "lc");

            Assert.Multiple(() => {
                Assert.That(endpoints.Select(endpoint => endpoint.Connection).Order(),  Is.EqualTo(new[] { "csms", "lc" }));
                Assert.That(lc?.ServerKeyPins,                                           Is.EqualTo(new[] { current, next }));
                Assert.That(lc?.Version,                                                 Is.EqualTo(12));
                Assert.That(lc?.State,                                                   Is.EqualTo("Confirmed"));
                Assert.That(lc?.Learned,                                                 Is.Null);
                Assert.That(lc?.Shown,                                                   Is.EqualTo(current));
                Assert.That(lc?.URL,                                                     Is.EqualTo("wss://lc001/cs001"));
            });

        }

        #endregion

    }

}
