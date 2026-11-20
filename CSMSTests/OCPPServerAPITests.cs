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

using System.Net;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.CSMS.OCPP;
using cloud.charging.open.protocols.OCPP.Node.Serving;
using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The routes the charging station server pages sit on.
    /// </summary>
    /// <remarks>
    /// The CSMS under here is switched on but its charging station server
    /// is not: what is being tested is the layer between the browser and the
    /// stores, and a socket bound to every interface is not needed to test it -
    /// nor wanted on a machine running tests.
    /// </remarks>
    public class OCPPServerAPITests : ACSMSTests
    {

        #region (private) Root

        private const String Root = "/api/v1/configuration/ocpp-server";

        #endregion


        #region TheServerSaysWhatItIsAndWhatItIsNotDoing()

        [Test]
        public async Task TheServerSaysWhatItIsAndWhatItIsNotDoing()
        {

            using var http = await SignedIn();

            var server = await GetJSON(http, Root);

            Assert.Multiple(() => {

                Assert.That(server.Value<Boolean>("enabled"),                Is.False,
                            "A CSMS nobody configured is listening for charging stations.");

                Assert.That(server.Value<Int32>("port"),                     Is.EqualTo(2352));
                Assert.That(server["clientAuthentication"]?.Values<String>(), Is.EquivalentTo(new[] { "httpAuthWithoutTLS", "httpAuthOverTLS", "tlsClientCertificate" }));
                Assert.That(server["subprotocols"]?.Values<String>(),        Is.EquivalentTo(new[] { "ocpp2.1", "ocpp2.0.1" }));
                Assert.That(server["state"]?.Value<Boolean>("running"),      Is.False);
                Assert.That(server["state"]?.Value<Boolean>("tls"),          Is.False);
                Assert.That(server["state"]?.Value<Boolean>("hasCertificate"), Is.False);
                Assert.That(server["logging"]?.Value<Boolean>("payloads"),   Is.False,
                            "The contents of OCPP messages are being logged by default.");

            });

        }

        #endregion

        #region NobodySignedInSeesNoneOfIt()

        [Test]
        public async Task NobodySignedInSeesNoneOfIt()
        {

            using var http = Anonymous();

            foreach (var path in new[] { Root, $"{Root}/trust", $"{Root}/logins" })
            {
                var response = await http.GetAsync(path);
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized), $"GET {path}");
            }

        }

        #endregion

        #region WhatIsSavedIsWhatComesBack()

        [Test]
        public async Task WhatIsSavedIsWhatComesBack()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync(
                                     Root,
                                     JSONBody(
                                         new JProperty("port",         9500),
                                         new JProperty("reachableAs",  new JArray("csms001.example.org"))
                                     )
                                 );

            Assert.That(response.IsSuccessStatusCode, Is.True, await response.Content.ReadAsStringAsync());

            var saved = JObject.Parse(await response.Content.ReadAsStringAsync());

            Assert.Multiple(() => {

                Assert.That(saved.Value<Int32>("port"),               Is.EqualTo(9500));
                Assert.That(saved["reachableAs"]?.Values<String>(),   Is.EquivalentTo(new[] { "csms001.example.org" }));

                // The port belongs to the socket, and the socket was opened
                // before this request; saying so is the whole point.
                Assert.That(saved["state"]?["waitingForARestart"]?.Values<String>(), Does.Contain("port"));

                // And what does not belong to the socket is not claimed to be
                // waiting for one.
                Assert.That(saved["state"]?["waitingForARestart"]?.Values<String>(), Does.Not.Contain("reachableAs"));

            });

            // And it is in the file, not only in memory.
            Assert.That(await File.ReadAllTextAsync(CSMS.ConfigFile.Path), Does.Contain("9500"));

        }

        #endregion

        #region SomethingTheControllerRefusesChangesNothing()

        [Test]
        public async Task SomethingTheControllerRefusesChangesNothing()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync(
                                     Root,
                                     JSONBody(new JProperty("clientAuthentication", new JArray("securityProfile4")))
                                 );

            Assert.Multiple(() => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(CSMS.OCPPSecurityProfiles,                Is.EquivalentTo(new Byte[] { 1, 2, 3 }));
            });

        }

        #endregion

        #region TLSOnlyIsRefusedWhileThereIsNoCertificate()

        /// <summary>
        /// Profiles 2 and 3 both need TLS, and without a certificate this port
        /// does not encrypt - so saving that would be saving a port through
        /// which nothing can come.
        /// </summary>
        [Test]
        public async Task TLSOnlyIsRefusedWhileThereIsNoCertificate()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync(
                                     Root,
                                     JSONBody(new JProperty("clientAuthentication", new JArray("httpAuthOverTLS", "tlsClientCertificate")))
                                 );

            await Assert.MultipleAsync(async () => {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("no server certificate"));
            });

        }

        #endregion

        #region MessageContentsCannotBeSwitchedOnIntoThePast()

        [Test]
        public async Task MessageContentsCannotBeSwitchedOnIntoThePast()
        {

            using var http = await SignedIn();

            var response = await http.PutAsync(
                                     Root,
                                     JSONBody(new JProperty("logging", new JObject(
                                         new JProperty("payloads",       true),
                                         new JProperty("payloadsUntil",  DateTimeOffset.UtcNow.AddHours(-1).ToString("o"))
                                     )))
                                 );

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest),
                        await response.Content.ReadAsStringAsync());

        }

        #endregion


        #region AServerChangeTheConfigurationFileCannotTakeIsAServerError()

        /// <summary>
        /// A change of the charging station server that is fine in itself, and
        /// that the configuration file cannot be written with, is answered 500
        /// with why - and put into effect nowhere - rather than with the 400 of
        /// what could have been wrong with it: nothing was. It was the status
        /// of the refusals, as it was on the routes of the logins, the keys and
        /// the chains.
        /// </summary>
        [Test]
        public async Task AServerChangeTheConfigurationFileCannotTakeIsAServerError()
        {

            using var http = await SignedIn();

            // Where the file's next version is written first is a directory.
            System.IO.Directory.CreateDirectory(CSMS.ConfigFile.Path + ".tmp");

            var response = await http.PutAsync(Root, JSONBody(new JProperty("reachableAs", new JArray("csms001.example.org"))));
            var body     = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                         Is.EqualTo(HttpStatusCode.InternalServerError), body);
                Assert.That(JObject.Parse(body).Value<String>("error"),  Does.StartWith($"'{CSMS.ConfigFile.Path}' could not be written: "));
                Assert.That(CSMS.OCPPServerSettings.ReachableAs ?? [],   Is.Empty, "the change was put into effect all the same");
            });

        }

        #endregion

        #region ARefusedServerChangeIsWhatItWasWhileTheFileCannotBeWritten()

        /// <summary>
        /// What was wrong with a change of the charging station server is
        /// answered as it was while the configuration file cannot be written:
        /// a 500 is the file's, and only where it was the file that refused.
        /// </summary>
        [Test]
        public async Task ARefusedServerChangeIsWhatItWasWhileTheFileCannotBeWritten()
        {

            using var http = await SignedIn();

            System.IO.Directory.CreateDirectory(CSMS.ConfigFile.Path + ".tmp");

            var noSuchProfile  = await http.PutAsync(Root, JSONBody(new JProperty("clientAuthentication", new JArray("securityProfile4"))));
            var tlsAlone       = await http.PutAsync(Root, JSONBody(new JProperty("clientAuthentication", new JArray("httpAuthOverTLS", "tlsClientCertificate"))));
            var pastWindow     = await http.PutAsync(Root, JSONBody(new JProperty("logging", new JObject(
                                                                  new JProperty("payloads",       true),
                                                                  new JProperty("payloadsUntil",  DateTimeOffset.UtcNow.AddHours(-1).ToString("o"))
                                                              ))));

            Assert.Multiple(() => {
                Assert.That(noSuchProfile.StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  "a security profile there is none of");
                Assert.That(tlsAlone.     StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  "TLS alone, and no certificate to speak it with");
                Assert.That(pastWindow.   StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  "message contents logged until a time gone by");
            });

        }

        #endregion


        #region AChainIsAcceptedSwitchedOffAndRemoved()

        [Test]
        public async Task AChainIsAcceptedSwitchedOffAndRemoved()
        {

            using var http = await SignedIn();
            using var ca   = TestCA.Create("Some Charging Network");

            var added = await http.PostAsync(
                                  $"{Root}/trust",
                                  JSONBody(
                                      new JProperty("pem",   TestCA.ToPEM(ca.Certificate)),
                                      new JProperty("name",  "Some Charging Network")
                                  )
                              );

            Assert.That(added.StatusCode, Is.EqualTo(HttpStatusCode.Created), await added.Content.ReadAsStringAsync());

            var id = JObject.Parse(await added.Content.ReadAsStringAsync()).Value<String>("id")!;

            var off = await http.PutAsync($"{Root}/trust/{id}", JSONBody(new JProperty("enabled", false)));

            Assert.That(off.IsSuccessStatusCode, Is.True);
            Assert.That(JObject.Parse(await off.Content.ReadAsStringAsync()).Value<Int32>("enabled"), Is.EqualTo(0));

            var gone = await http.DeleteAsync($"{Root}/trust/{id}");

            Assert.Multiple(() => {
                Assert.That(gone.IsSuccessStatusCode,        Is.True);
                Assert.That(CSMS.ClientTrust.Entries,  Is.Empty);
            });

        }

        #endregion

        #region SomethingThatIsNotACertificateAuthorityIsRefused()

        [Test]
        public async Task SomethingThatIsNotACertificateAuthorityIsRefused()
        {

            using var http = await SignedIn();

            var response = await http.PostAsync(
                                     $"{Root}/trust",
                                     JSONBody(new JProperty("pem", "trust us, we are a charging network"))
                                 );

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));

        }

        #endregion

        #region AChangeTheChainFilesCannotTakeIsAServerError(Change)

        /// <summary>
        /// A change of the accepted chains that is fine in itself, and that
        /// their files cannot be written with, is answered 500 with why, rather
        /// than with the 400 of what could have been wrong with it: nothing was.
        /// Every route that writes those files. It was the status of the
        /// refusals, as it was on the stations file's routes. And it changes
        /// nothing, now or when the store is read again.
        /// </summary>
        [TestCase("POST trust")]
        [TestCase("POST trust, after its chain")]
        [TestCase("PUT trust/{id}, name")]
        [TestCase("PUT trust/{id}, enabled")]
        public async Task AChangeTheChainFilesCannotTakeIsAServerError(String Change)
        {

            using var http = await SignedIn();
            using var ca   = TestCA.Create("Some Charging Network");

            // What makes each change a fine one: a chain accepted already.
            String? chainId  = null;

            // The handle the store gives the chain: its anchor's, and so known
            // before the chain is there.
            var anchorId     = Convert.ToHexStringLower(SHA256.HashData(ca.Certificate.RawData).AsSpan(0, 8));

            if (Change.StartsWith("PUT trust", StringComparison.Ordinal))
            {

                var added = await http.PostAsync($"{Root}/trust", JSONBody(new JProperty("pem", TestCA.ToPEM(ca.Certificate))));

                Assert.That(added.StatusCode, Is.EqualTo(HttpStatusCode.Created), await added.Content.ReadAsStringAsync());

                chainId = JObject.Parse(await added.Content.ReadAsStringAsync()).Value<String>("id")!;

            }

            var chainsBefore  = Chains();

            // Where each change is written, something it cannot be written to.
            var blocked = Change switch {
                "POST trust"                   => CSMS.ClientTrust.Path,
                // What is said of the chain, which is written after the chain.
                "POST trust, after its chain"  => System.IO.Path.Combine(CSMS.ClientTrust.Path,        $"{anchorId}.json"),
                _                              => System.IO.Path.Combine(CSMS.ClientTrust.Path,        $"{chainId}.json")
            };

            if (Change == "POST trust")
                AFileWhere(blocked);
            else
                ADirectoryWhere(blocked);

            var response = Change switch {
                "POST trust" or
                "POST trust, after its chain"  => await http.PostAsync($"{Root}/trust",                JSONBody(new JProperty("pem",        TestCA.ToPEM(ca.Certificate)))),
                "PUT trust/{id}, name"         => await http.PutAsync ($"{Root}/trust/{chainId}",       JSONBody(new JProperty("name",       "Another Charging Network"))),
                "PUT trust/{id}, enabled"      => await http.PutAsync ($"{Root}/trust/{chainId}",       JSONBody(new JProperty("enabled",    false))),
                _                              => throw new ArgumentException($"No change '{Change}' here.", nameof(Change))
            };

            var body          = await response.Content.ReadAsStringAsync();

            var chainsNow     = Chains();

            // And as at the next start: read again, with nothing in the way.
            NothingWhere(blocked);

            CSMS.ClientTrust.Reload();

            var chainsAgain   = Chains();

            Assert.Multiple(() => {

                Assert.That(response.StatusCode,                         Is.EqualTo(HttpStatusCode.InternalServerError), body);
                Assert.That(JObject.Parse(body).Value<String>("error"),  Does.Contain(CSMS.ClientTrust.Path));

                Assert.That(chainsNow,    Is.EqualTo(chainsBefore),  "the chains accepted");
                Assert.That(chainsAgain,  Is.EqualTo(chainsBefore),  "the chains accepted, read again: a chain written without what is said of it " +
                                                                     "was accepted at the next start, switched on and named by its subject");

                Assert.That(File.Exists(System.IO.Path.Combine(CSMS.ClientTrust.Path, $"{anchorId}.pem")),
                            Is.EqualTo(Change.StartsWith("PUT trust", StringComparison.Ordinal)),
                            "the chain's file, there only where the chain was accepted before");

            });

            String[] Chains()
                => [.. CSMS.ClientTrust.Entries.Select(entry => $"{entry.Id} '{entry.Name}' {(entry.Enabled ? "on" : "off")}")];

        }

        #endregion

        #region AChainWhoseFilesCannotBeRemovedIsAServerError()

        /// <summary>
        /// A chain that is here, but whose files cannot be removed, is answered
        /// 500 with why, rather than with the 404 of one that is not here.
        /// </summary>
        /// <remarks>
        /// Windows's alone: a file held open without leave to delete it stays
        /// there on Windows, where Linux lets it go all the same - and root
        /// takes it out of a directory it may not write to as well.
        /// </remarks>
        [Test]
        [Platform("Win")]
        public async Task AChainWhoseFilesCannotBeRemovedIsAServerError()
        {

            using var http = await SignedIn();
            using var ca   = TestCA.Create("Some Charging Network");

            var id     = JObject.Parse(await (await http.PostAsync($"{Root}/trust",
                             JSONBody(new JProperty("pem", TestCA.ToPEM(ca.Certificate))))).Content.ReadAsStringAsync()).Value<String>("id")!;

            var file   = System.IO.Path.Combine(CSMS.ClientTrust.Path, $"{id}.pem");
            var route  = $"{Root}/trust/{id}";

            HttpResponseMessage response;

            using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                response = await http.DeleteAsync(route);

            var body = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                         Is.EqualTo(HttpStatusCode.InternalServerError), body);
                Assert.That(JObject.Parse(body).Value<String>("error"),  Does.StartWith($"'{id}' could not be removed from "));
            });

        }

        #endregion

        #region ADeletionItsLastFileDoesNotLetHappenLeavesEveryFile()

        /// <summary>
        /// A chain whose last file cannot be deleted keeps all of its files,
        /// and is there when it is read again. Deleted one after the other, the
        /// files before it were gone: the chain's certificates - and the chain,
        /// listed until the next start, was gone after it (found by the
        /// charging station).
        /// </summary>
        [Test]
        [Platform("Win", Reason = "A file somebody holds open is deleted all the same on Linux, and a test run as root there deletes what it likes: nothing but Windows keeps a file from being deleted.")]
        public async Task ADeletionItsLastFileDoesNotLetHappenLeavesEveryFile()
        {

            using var http  = await SignedIn();
            using var ca    = TestCA.Create("Some Charging Network");

            var id         = JObject.Parse(await (await http.PostAsync($"{Root}/trust",
                                 JSONBody(new JProperty("pem", TestCA.ToPEM(ca.Certificate))))).Content.ReadAsStringAsync()).Value<String>("id")!;

            var directory  = CSMS.ClientTrust.Path;

            String[] FilesOf() => System.IO.Directory.GetFiles(directory, $"{id}.*").Order(StringComparer.Ordinal).Select(file => System.IO.Path.GetFileName(file)).ToArray();

            var before = FilesOf();

            HttpResponseMessage response;

            // The description is the last of its files to be taken away.
            using (new FileStream(System.IO.Path.Combine(directory, $"{id}.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
                response = await http.DeleteAsync($"{Root}/trust/{id}");

            var body   = await response.Content.ReadAsStringAsync();
            var after  = FilesOf();

            CSMS.ClientTrust.Reload();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,  Is.EqualTo(HttpStatusCode.InternalServerError), body);
                Assert.That(before,               Has.Length.GreaterThan(1),  "a chain of one file");
                Assert.That(after,                Is.EqualTo(before),         "its files");
                Assert.That(CSMS.ClientTrust.Entries.Select(entry => entry.Id),
                            Does.Contain(id), "read again");
            });

        }

        #endregion

        #region ARefusalOfAChainIsWhatItWasWhileItsFilesCannotBeWritten()

        /// <summary>
        /// What was wrong with a change of the chains is answered as it was
        /// while their files cannot be written: a 500 is the files', and only
        /// where it was the files that refused.
        /// </summary>
        [Test]
        public async Task ARefusalOfAChainIsWhatItWasWhileItsFilesCannotBeWritten()
        {

            using var http = await SignedIn();

            AFileWhere(CSMS.ClientTrust.Path);

            var notAChain         = await http.PostAsync  ($"{Root}/trust",                         JSONBody(new JProperty("pem",       "trust us, we are a charging network")));
            var noChainToName     = await http.PutAsync   ($"{Root}/trust/0123456789abcdef",        JSONBody(new JProperty("name",      "Another Charging Network")));
            var noSuchChain       = await http.DeleteAsync($"{Root}/trust/0123456789abcdef");

            Assert.Multiple(() => {
                Assert.That(notAChain.       StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  "a chain that is none");
                Assert.That(noChainToName.   StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  "a chain that is not here, to name");
                Assert.That(noSuchChain.     StatusCode,  Is.EqualTo(HttpStatusCode.NotFound),    "a chain that is not here");
            });

        }

        #endregion

        #region (private static) AFileWhere(Directory) / ADirectoryWhere(File) / NothingWhere(Path)

        /// <summary>
        /// A file where a store keeps its directory, so that nothing can be
        /// written below it - on Linux as on Windows, and for root as for
        /// anybody else, which a directory without write permission is not.
        /// </summary>
        private static void AFileWhere(String Directory)
        {

            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Move(Directory, Directory + ".aside");

            System.IO.File.WriteAllText(Directory, "");

        }

        /// <summary>
        /// A directory where a store writes one of its files.
        /// </summary>
        private static void ADirectoryWhere(String File)
        {

            if (System.IO.File.Exists(File))
                System.IO.File.Move(File, File + ".aside");

            System.IO.Directory.CreateDirectory(File);

        }

        /// <summary>
        /// Nothing in the way any more of <see cref="AFileWhere"/> or
        /// <see cref="ADirectoryWhere"/>: what was there before is back.
        /// </summary>
        private static void NothingWhere(String Path)
        {

            if (System.IO.File.Exists(Path))
                System.IO.File.Delete(Path);

            else if (System.IO.Directory.Exists(Path))
                System.IO.Directory.Delete(Path);

            if (System.IO.Directory.Exists(Path + ".aside"))
                System.IO.Directory.Move(Path + ".aside", Path);

            else if (System.IO.File.Exists(Path + ".aside"))
                System.IO.File.Move(Path + ".aside", Path);

        }

        #endregion


        #region AStationIsAddedWithItsPasswordWhichIsNotShownAgain()

        /// <summary>
        /// The password is given, and none is made up: it is kept only as a
        /// hash, and neither the answer nor the list shows it again.
        /// </summary>
        [Test]
        public async Task AStationIsAddedWithItsPasswordWhichIsNotShownAgain()
        {

            using var http = await SignedIn();

            const String password = "a-password-long-enough-for-ocpp";

            var none  = await http.PostAsync(
                                  $"{Root}/logins",
                                  JSONBody(
                                      new JProperty("id",    "cs001"),
                                      new JProperty("description",  new JObject(new JProperty("en", "Ladepunkt 1")))
                                  )
                              );

            Assert.That(none.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest), "A charging station was added without a password.");

            var added = await http.PostAsync(
                                  $"{Root}/logins",
                                  JSONBody(
                                      new JProperty("id",        "cs001"),
                                      new JProperty("password",  password),
                                      new JProperty("description",      new JObject(new JProperty("en", "Ladepunkt 1")))
                                  )
                              );

            Assert.That(added.IsSuccessStatusCode, Is.True, await added.Content.ReadAsStringAsync());

            var answer = await added.Content.ReadAsStringAsync();

            await Assert.MultipleAsync(async () => {

                Assert.That(CSMS.WebSocketLogins.Verify("cs001", password), Is.True);
                Assert.That(answer,                                       Does.Not.Contain(password));

                var listed = await GetJSON(http, $"{Root}/logins");

                Assert.That(listed.ToString(), Does.Not.Contain(password));
                Assert.That(listed.ToString(), Does.Not.Contain("$pbkdf2"));
                Assert.That(listed["logins"]?[0]?["description"]?.Value<String>("en"), Is.EqualTo("Ladepunkt 1"));

            });

        }

        #endregion

        #region AStationIsShutOutAndForgotten()

        [Test]
        public async Task AStationIsShutOutAndForgotten()
        {

            using var http = await SignedIn();

            const String password = "a-password-long-enough-for-ocpp";

            await http.PostAsync($"{Root}/logins", JSONBody(new JProperty("id", "cs001"), new JProperty("password", password)));

            await http.PutAsync($"{Root}/logins/cs001", JSONBody(new JProperty("enabled", false)));

            Assert.That(CSMS.WebSocketLogins.Verify("cs001", password), Is.False);

            var gone = await http.DeleteAsync($"{Root}/logins/cs001");

            Assert.Multiple(() => {
                Assert.That(gone.IsSuccessStatusCode,        Is.True);
                Assert.That(CSMS.WebSocketLogins.Logins, Is.Empty);
            });

        }

        #endregion

        #region AStationThisControllerNeverHeardOfIsANotFound()

        [Test]
        public async Task AStationThisControllerNeverHeardOfIsANotFound()
        {

            using var http = await SignedIn();

            var response = await http.DeleteAsync($"{Root}/logins/cs404");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));

        }

        #endregion

        #region AChangeTheStationsFileCannotTakeIsAServerError(Change)

        /// <summary>
        /// A change of the logins that is fine in itself, and that the stations
        /// file cannot be written with, is answered 500 with why - the change
        /// undone - rather than with the 400, 404 or 409 of what was wrong with
        /// it: nothing was. Every route that writes the file. It was the status
        /// of the refusals, and a full disk was a station "not found".
        /// </summary>
        [TestCase("POST groups")]
        [TestCase("PUT groups/{id}")]
        [TestCase("DELETE groups/{id}")]
        [TestCase("POST stations")]
        [TestCase("PUT stations/{id}, enabled")]
        [TestCase("PUT stations/{id}, group")]
        [TestCase("PUT stations/{id}/totp")]
        [TestCase("DELETE stations/{id}/totp")]
        [TestCase("PUT stations/{id}/totp/binding")]
        [TestCase("DELETE stations/{id}/password")]
        [TestCase("DELETE stations/{id}")]
        public async Task AChangeTheStationsFileCannotTakeIsAServerError(String Change)
        {

            using var http = await SignedIn();

            // What makes each change a fine one: a station with a password and
            // a token, in the default group, and a group of its own, empty.
            foreach (var made in new[] {
                                     await http.PostAsync($"{Root}/logins",           JSONBody(new JProperty("id", "cs001"), new JProperty("password", "a-password-long-enough-for-ocpp"))),
                                     await http.PutAsync ($"{Root}/logins/cs001/totp", JSONBody()),
                                     await http.PostAsync($"{Root}/groups",             JSONBody(new JProperty("id", "field-test")))
                                 })
                Assert.That(made.IsSuccessStatusCode, Is.True, await made.Content.ReadAsStringAsync());

            // Where the file's next version is written first is a directory.
            System.IO.Directory.CreateDirectory(CSMS.WebSocketLogins.Path + ".tmp");

            var response = Change switch {
                "POST groups"                    => await http.PostAsync  ($"{Root}/groups",                 JSONBody(new JProperty("id",      "another"))),
                "PUT groups/{id}"                => await http.PutAsync   ($"{Root}/groups/field-test",      JSONBody(new JProperty("enabled", false))),
                "DELETE groups/{id}"             => await http.DeleteAsync($"{Root}/groups/field-test"),
                "POST stations"                  => await http.PostAsync  ($"{Root}/logins",               JSONBody(new JProperty("id",      "cs002"), new JProperty("password", "a-password-long-enough-for-ocpp"))),
                "PUT stations/{id}, enabled"     => await http.PutAsync   ($"{Root}/logins/cs001",         JSONBody(new JProperty("enabled", false))),
                "PUT stations/{id}, group"       => await http.PutAsync   ($"{Root}/logins/cs001",         JSONBody(new JProperty("group",   "field-test"))),
                "PUT stations/{id}/totp"         => await http.PutAsync   ($"{Root}/logins/cs001/totp",    JSONBody()),
                "DELETE stations/{id}/totp"      => await http.DeleteAsync($"{Root}/logins/cs001/totp"),
                "PUT stations/{id}/totp/binding" => await http.PutAsync   ($"{Root}/logins/cs001/totp/binding", JSONBody(new JProperty("tlsChannelBinding", true))),
                "DELETE stations/{id}/password"  => await http.DeleteAsync($"{Root}/logins/cs001/password"),
                "DELETE stations/{id}"           => await http.DeleteAsync($"{Root}/logins/cs001"),
                _                                => throw new ArgumentException($"No change '{Change}' here.", nameof(Change))
            };

            var body = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                         Is.EqualTo(HttpStatusCode.InternalServerError), body);
                Assert.That(JObject.Parse(body).Value<String>("error"),  Does.StartWith($"'{CSMS.WebSocketLogins.Path}' could not be written: "));
            });

        }

        #endregion

        #region ARefusalIsWhatItWasWhileTheStationsFileCannotBeWritten()

        /// <summary>
        /// What was wrong with a change is answered as it was while the stations
        /// file cannot be written: a 500 is the file's, and only where it was the
        /// file that refused. Named after the file, for the kit's test of the
        /// configuration file had the same name, and the two could not be told
        /// apart in a TRX, which names a test by its method alone.
        /// </summary>
        [Test]
        public async Task ARefusalIsWhatItWasWhileTheStationsFileCannotBeWritten()
        {

            using var http = await SignedIn();

            var added = await http.PostAsync($"{Root}/logins", JSONBody(new JProperty("id", "cs001"), new JProperty("group", "default"), new JProperty("password", "a-password-long-enough-for-ocpp")));
            Assert.That(added.IsSuccessStatusCode, Is.True, await added.Content.ReadAsStringAsync());

            System.IO.Directory.CreateDirectory(CSMS.WebSocketLogins.Path + ".tmp");

            var unknown   = await http.DeleteAsync($"{Root}/logins/cs404");
            var tooShort  = await http.PostAsync  ($"{Root}/logins",               JSONBody(new JProperty("id", "cs002"), new JProperty("password", "short")));
            var notEmpty  = await http.DeleteAsync($"{Root}/groups/default");
            var noToken   = await http.DeleteAsync($"{Root}/logins/cs001/totp");

            Assert.Multiple(() => {
                Assert.That(unknown. StatusCode,  Is.EqualTo(HttpStatusCode.NotFound),    "a station this CSMS never heard of");
                Assert.That(tooShort.StatusCode,  Is.EqualTo(HttpStatusCode.BadRequest),  "a password too short");
                Assert.That(notEmpty.StatusCode,  Is.EqualTo(HttpStatusCode.Conflict),    "a group somebody is in");
                Assert.That(noToken. StatusCode,  Is.EqualTo(HttpStatusCode.NotFound),    "a token that is not there to take away");
            });

        }

        #endregion

        #region NobodySignedInChangesNoLoginsAndNoGroups()

        /// <summary>
        /// The write routes are the ones worth trying uninvited, and a refusal
        /// has to come before this CSMS says anything about the body.
        /// </summary>
        [Test]
        public async Task NobodySignedInChangesNoLoginsAndNoGroups()
        {

            using var http = Anonymous();

            var attempts = new (String What, Task<HttpResponseMessage> Response)[] {
                ("POST groups",           http.PostAsync  ($"{Root}/groups",                   JSONBody(new JProperty("id", "sneaky")))),
                ("PUT groups/{id}",       http.PutAsync   ($"{Root}/groups/default",           JSONBody(new JProperty("enabled", false)))),
                ("DELETE groups/{id}",    http.DeleteAsync($"{Root}/groups/default")),
                ("POST stations",         http.PostAsync  ($"{Root}/logins",                 JSONBody(new JProperty("id", "cs666"), new JProperty("password", "a-password-long-enough-for-ocpp")))),
                ("PUT stations/../totp",  http.PutAsync   ($"{Root}/logins/cs001/totp",      JSONBody())),
                ("DELETE ../totp",        http.DeleteAsync($"{Root}/logins/cs001/totp")),
                ("DELETE ../password",    http.DeleteAsync($"{Root}/logins/cs001/password"))
            };

            foreach (var (what, response) in attempts)
                Assert.That((await response).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized), what);

            Assert.Multiple(() => {
                Assert.That(CSMS.WebSocketLogins.Logins,                        Is.Empty);
                Assert.That(CSMS.WebSocketLogins.GetGroup("sneaky"),            Is.Null);
                Assert.That(CSMS.WebSocketLogins.GetGroup(WebSocketLoginGroup.DefaultId), Is.Not.Null);
                Assert.That(CSMS.WebSocketLogins.GetGroup(WebSocketLoginGroup.DefaultId)!.Enabled, Is.True);
            });

        }

        #endregion

        #region AGroupIsMadeNarrowedAndRemoved()

        [Test]
        public async Task AGroupIsMadeNarrowedAndRemoved()
        {

            using var http = await SignedIn();

            var made = await http.PostAsync(
                                 $"{Root}/groups",
                                 JSONBody(
                                     new JProperty("id",                "field-test"),
                                     new JProperty("name",              "Field test"),
                                     new JProperty("enabled",           true),
                                     new JProperty("authMethods",       new JArray("basic", "totp")),
                                     new JProperty("clientAuthentication",  new JArray("httpAuthWithoutTLS", "httpAuthOverTLS"))
                                 )
                             );

            Assert.That(made.IsSuccessStatusCode, Is.True, await made.Content.ReadAsStringAsync());

            var group = CSMS.WebSocketLogins.GetGroup("field-test");

            Assert.That(group, Is.Not.Null);

            Assert.Multiple(() => {
                Assert.That(group!.AuthMethods,       Is.EquivalentTo(new[] { AuthMethod.Basic, AuthMethod.TOTP }));
                Assert.That(group.ClientAuthentication,   Is.EquivalentTo(new[] { WebSocketClientAuthentication.HTTPAuthWithoutTLS, WebSocketClientAuthentication.HTTPAuthOverTLS }));
                Assert.That(group.Allows(AuthMethod.Certificate), Is.False);
            });

            // Everything is replaced, not merged - which is what makes taking
            // the last method away possible at all.
            var narrowed = await http.PutAsync(
                                     $"{Root}/groups/field-test",
                                     JSONBody(
                                         new JProperty("name",              "Field test"),
                                         new JProperty("enabled",           true),
                                         new JProperty("authMethods",       new JArray("totp")),
                                         new JProperty("clientAuthentication",  new JArray("httpAuthOverTLS"))
                                     )
                                 );

            Assert.That(narrowed.IsSuccessStatusCode, Is.True, await narrowed.Content.ReadAsStringAsync());

            Assert.Multiple(() => {
                Assert.That(CSMS.WebSocketLogins.GetGroup("field-test")!.Allows(AuthMethod.Basic),  Is.False);
                Assert.That(CSMS.WebSocketLogins.GetGroup("field-test")!.Allows(WebSocketClientAuthentication.HTTPAuthWithoutTLS),          Is.False);
            });

            var gone = await http.DeleteAsync($"{Root}/groups/field-test");

            Assert.Multiple(() => {
                Assert.That(gone.IsSuccessStatusCode,                   Is.True);
                Assert.That(CSMS.WebSocketLogins.GetGroup("field-test"), Is.Null);
            });

        }

        #endregion

        #region AGroupSomebodyIsStillInIsAConflictAndNotASilentMove()

        [Test]
        public async Task AGroupSomebodyIsStillInIsAConflictAndNotASilentMove()
        {

            using var http = await SignedIn();

            await http.PostAsync($"{Root}/groups",
                                 JSONBody(new JProperty("id",           "field-test"),
                                          new JProperty("authMethods",  new JArray("basic")),
                                          new JProperty("clientAuthentication", new JArray("httpAuthWithoutTLS"))));

            await http.PostAsync($"{Root}/logins",
                                 JSONBody(new JProperty("id",        "cs001"),
                                          new JProperty("group",     "field-test"),
                                          new JProperty("password",  "a-password-long-enough-for-ocpp")));

            var refused = await http.DeleteAsync($"{Root}/groups/field-test");

            Assert.Multiple(() => {
                Assert.That(refused.StatusCode,                              Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(CSMS.WebSocketLogins.GetGroup("field-test"),  Is.Not.Null);
                Assert.That(CSMS.WebSocketLogins.Logins.Single().GroupId, Is.EqualTo("field-test"));
            });

        }

        #endregion

        #region ASharedSecretIsHandedOutOnceAndNeverListed()

        [Test]
        public async Task ASharedSecretIsHandedOutOnceAndNeverListed()
        {

            using var http = await SignedIn();

            await http.PostAsync($"{Root}/logins", JSONBody(new JProperty("id", "cs001"), new JProperty("password", "a-password-long-enough-for-ocpp")));

            var given = await http.PutAsync($"{Root}/logins/cs001/totp", JSONBody());

            Assert.That(given.IsSuccessStatusCode, Is.True, await given.Content.ReadAsStringAsync());

            var answer = JObject.Parse(await given.Content.ReadAsStringAsync());
            var secret = answer.Value<String>("sharedSecret");

            await Assert.MultipleAsync(async () => {

                Assert.That(secret, Is.Not.Null.And.Not.Empty,
                            "No shared secret came back, so nobody can configure the charging station.");

                Assert.That(CSMS.WebSocketLogins.TryGet("cs001", out var login) && login.HasTOTP, Is.True);

                // The list the page reads must never carry it, however often it
                // is asked - this is the one credential that works as it stands.
                var listed = await GetJSON(http, $"{Root}/logins");

                Assert.That(listed.ToString(), Does.Not.Contain(secret!));
                Assert.That(listed["logins"]?[0]?.Value<Boolean>("hasTOTP"), Is.True);

            });

        }

        #endregion

        #region ATokenIsTakenAwayAgain()

        /// <summary>
        /// Whether a token has to be bound to its connection is its own
        /// request, which hands out no secret: the one there is stays.
        /// </summary>
        [Test]
        public async Task ATokenIsToldToBeBound_AndNoLonger()
        {

            using var http = await SignedIn();

            await http.PostAsync($"{Root}/logins", JSONBody(new JProperty("id", "cs001"), new JProperty("password", "a-password-long-enough-for-ocpp")));

            var nothingYet  = await http.PutAsync($"{Root}/logins/cs001/totp/binding", JSONBody(new JProperty("tlsChannelBinding", true)));

            await http.PutAsync ($"{Root}/logins/cs001/totp", JSONBody());

            CSMS.WebSocketLogins.TryGet("cs001", out var before);

            var mistyped    = await http.PutAsync($"{Root}/logins/cs001/totp/binding", JSONBody(new JProperty("tlsChannelBinding", "yes")));
            var bound       = await http.PutAsync($"{Root}/logins/cs001/totp/binding", JSONBody(new JProperty("tlsChannelBinding", true)));
            var answer      = JObject.Parse(await bound.Content.ReadAsStringAsync());

            CSMS.WebSocketLogins.TryGet("cs001", out var after);

            var unbound     = await http.PutAsync($"{Root}/logins/cs001/totp/binding", JSONBody(new JProperty("tlsChannelBinding", false)));

            CSMS.WebSocketLogins.TryGet("cs001", out var atLast);

            Assert.Multiple(() => {
                Assert.That((Int32) nothingYet.StatusCode,           Is.EqualTo(404),  "a token that is not there was bound");
                Assert.That((Int32) mistyped.  StatusCode,           Is.EqualTo(400));
                Assert.That(bound.IsSuccessStatusCode,               Is.True);
                Assert.That(after?.TOTP?.TLSChannelBinding,          Is.True);
                Assert.That(after?.TOTP?.SharedSecret,               Is.EqualTo(before?.TOTP?.SharedSecret),  "the secret was changed");
                Assert.That(answer.ToString(),                       Does.Not.Contain(before!.TOTP!.SharedSecret));
                Assert.That(answer["logins"]?[0]?["totp"]?.Value<Boolean>("tlsChannelBinding"), Is.True);
                Assert.That(unbound.IsSuccessStatusCode,             Is.True);
                Assert.That(atLast?.TOTP?.TLSChannelBinding,         Is.False);
            });

        }

        [Test]
        public async Task ATokenIsTakenAwayAgain()
        {

            using var http = await SignedIn();

            await http.PostAsync($"{Root}/logins", JSONBody(new JProperty("id", "cs001"), new JProperty("password", "a-password-long-enough-for-ocpp")));
            await http.PutAsync ($"{Root}/logins/cs001/totp", JSONBody());

            var gone = await http.DeleteAsync($"{Root}/logins/cs001/totp");

            Assert.Multiple(() => {
                Assert.That(gone.IsSuccessStatusCode, Is.True);
                Assert.That(CSMS.WebSocketLogins.TryGet("cs001", out var login) && login.HasTOTP, Is.False);
                Assert.That(CSMS.WebSocketLogins.TryGet("cs001", out var still) && still.HasPassword, Is.True,
                            "Taking the token away took the password with it.");
            });

        }

        #endregion

        #region ASecretThisControllerWouldThrowOnIsABadRequest()

        [Test]
        public async Task ASecretThisControllerWouldThrowOnIsABadRequest()
        {

            using var http = await SignedIn();

            await http.PostAsync($"{Root}/logins", JSONBody(new JProperty("id", "cs001"), new JProperty("password", "a-password-long-enough-for-ocpp")));

            var refused = await http.PutAsync(
                                    $"{Root}/logins/cs001/totp",
                                    JSONBody(new JProperty("sharedSecret", "short"))
                                );

            Assert.Multiple(() => {
                Assert.That(refused.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(CSMS.WebSocketLogins.TryGet("cs001", out var login) && login.HasTOTP, Is.False);
            });

        }

        #endregion

        #region TheOverallConfigurationMentionsTheStationServer()

        [Test]
        public async Task TheOverallConfigurationMentionsTheStationServer()
        {

            using var http = await SignedIn();

            var configuration = await GetJSON(http, "/api/v1/configuration");

            Assert.Multiple(() => {
                Assert.That(configuration["stationServer"],                          Is.Not.Null);
                Assert.That(configuration["stationServer"]?.Value<Boolean>("enabled"), Is.False);
                Assert.That(configuration["stationServer"]?.Value<String>("url"),      Does.StartWith("ws://"));
            });

        }

        #endregion

    }

}
