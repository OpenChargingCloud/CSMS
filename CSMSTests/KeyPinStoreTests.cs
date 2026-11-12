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

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.CSMS.OCPP;

#endregion

namespace cloud.charging.open.CSMS.Tests
{

    /// <summary>
    /// The store of the key pins: per local controller the pins last read of it, per station behind it the
    /// endpoint the pins are for, the version last sent and whether it was taken - kept beside the
    /// configuration file across restarts, and the routes to the stations put back from it.
    /// </summary>
    public class KeyPinStoreTests
    {

        #region Data

        private const String Current = "6a1f0c00000000000000000000000000000000000000000000000000009b2e01";
        private const String Next    = "c47d1800000000000000000000000000000000000000000000000000000003a5";

        private String  directory  = default!;

        private static readonly DateTimeOffset  At  = new (2026, 11, 12, 4, 0, 0, TimeSpan.Zero);

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeAnOpenDirectory()
        {
            directory = TestCSMSs.TemporaryDirectory("key-pins");
            Directory.CreateDirectory(directory);
            OwnerOnlyChecks.OpenToEverybody(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
        {
            TestCSMSs.Remove(directory);
        }

        #endregion

        #region (private) File / Reloaded()

        private String File
            => Path.Combine(directory, KeyPinStore.DefaultFileName);

        private KeyPinStore Reloaded()
        {
            var store = new KeyPinStore(File);
            store.Load();
            return store;
        }

        #endregion


        #region WhatIsNoted_IsReadBack_AfterARestart()

        /// <summary>
        /// A controller's pins, the stations behind it, the endpoint of each and the pin set it was last sent,
        /// taken or not, are read back by a store made anew from the file - which is its owner's alone.
        /// </summary>
        [Test]
        public void WhatIsNoted_IsReadBack_AfterARestart()
        {

            var store = new KeyPinStore(File);

            store.Load();

            Assert.Multiple(() => {
                Assert.That(store.NoteStation("cs001", "lc001", At),               Is.True,  "a station behind a controller is no news");
                Assert.That(store.NoteStation("cs001", "lc001", At.AddMinutes(1)), Is.False, "the same station behind the same controller is news again");
            });

            store.NoteStation ("cs002", "lc001", At);
            store.NotePins    ("lc001", Current, Next, At.AddDays(-30), At);
            store.NoteConnection("cs001", "lc", 3);
            store.NoteSent    ("cs001", "lc", 4, [ Current, Next ], At.AddMinutes(2), "Accepted", true);
            store.NoteConnection("cs002", "lc", 9);
            store.NoteSent    ("cs002", "lc", 10, [ Current, Next ], At.AddMinutes(3), "Rejected Unsigned: no signer", false);

            var reloaded    = Reloaded();
            var controller  = reloaded.Get("lc001");
            var cs001       = reloaded.StationOf("cs001");
            var cs002       = reloaded.StationOf("cs002");

            Assert.Multiple(() => {

                Assert.That(OwnerOnlyChecks.OthersMayGetIn(File),     Is.Empty, "others may read the key pins");

                Assert.That(controller?.CurrentKeyPin,               Is.EqualTo(Current));
                Assert.That(controller?.NextKeyPin,                  Is.EqualTo(Next));
                Assert.That(controller?.Pins,                        Is.EqualTo(new[] { Current, Next }));
                Assert.That(controller?.KeyCreated,                  Is.EqualTo(At.AddDays(-30)));
                Assert.That(controller?.Read,                        Is.EqualTo(At));
                Assert.That(controller?.Stations?.Select(station => station.Station), Is.EqualTo(new[] { "cs001", "cs002" }));

                Assert.That(reloaded.LocalControllerOf("cs001"),     Is.EqualTo("lc001"));
                Assert.That(cs001?.Noted,                            Is.EqualTo(At), "noting the station again changed when it was first noted");
                Assert.That(cs001?.Connection,                       Is.EqualTo("lc"));
                Assert.That(cs001?.Version,                          Is.EqualTo(4));
                Assert.That(cs001?.Pins,                             Is.EqualTo(new[] { Current, Next }));
                Assert.That(cs001?.Sent,                             Is.EqualTo(At.AddMinutes(2)));
                Assert.That(cs001?.Accepted,                         Is.True);

                Assert.That(cs002?.Version,                          Is.EqualTo(10), "the version last sent is not kept where it was refused");
                Assert.That(cs002?.Accepted,                         Is.False);
                Assert.That(cs002?.Answer,                           Is.EqualTo("Rejected Unsigned: no signer"));

            });

        }

        #endregion

        #region TheVersionReported_IsKeptUntilAPinSetIsSent()

        /// <summary>
        /// The version a station reported holding is kept until a pin set is sent; after that, the one sent is,
        /// whatever the next report said - and another endpoint is another version.
        /// </summary>
        [Test]
        public void TheVersionReported_IsKeptUntilAPinSetIsSent()
        {

            var store = new KeyPinStore(File);

            store.NoteStation   ("cs001", "lc001", At);
            store.NoteConnection("cs001", "lc", 3);

            var reported = store.StationOf("cs001")?.Version;

            store.NoteSent      ("cs001", "lc", 4, [ Current ], At, "Accepted", true);
            store.NoteConnection("cs001", "lc", 3);

            var sent     = store.StationOf("cs001")?.Version;

            store.NoteConnection("cs001", "other", 1);

            Assert.Multiple(() => {
                Assert.That(reported,                                Is.EqualTo(3));
                Assert.That(sent,                                    Is.EqualTo(4), "a report written over the version sent");
                Assert.That(store.StationOf("cs001")?.Connection,    Is.EqualTo("other"));
                Assert.That(store.StationOf("cs001")?.Version,       Is.EqualTo(1), "another endpoint kept the version of the one before");
            });

        }

        #endregion

        #region AStationThatMoved_IsTakenOffItsController()

        /// <summary>
        /// A station behind another controller is taken off the first; one that came straight to the CSMS is
        /// taken off every one.
        /// </summary>
        [Test]
        public void AStationThatMoved_IsTakenOffItsController()
        {

            var store = new KeyPinStore(File);

            store.NoteStation("cs001", "lc001", At);
            store.NoteStation("cs001", "lc002", At);

            var moved      = Reloaded();

            var forgotten  = store.ForgetStation("cs001");
            var again      = store.ForgetStation("cs001");

            Assert.Multiple(() => {
                Assert.That(moved.LocalControllerOf("cs001"),                           Is.EqualTo("lc002"));
                Assert.That(moved.Get("lc001")?.Stations?.Select(s => s.Station),     Is.Empty, "the station is still behind the controller it left");
                Assert.That(forgotten,                                                 Is.True);
                Assert.That(again,                                                     Is.False);
                Assert.That(Reloaded().LocalControllerOf("cs001"),                     Is.Null);
            });

        }

        #endregion

        #region AnUnreadableFile_IsPutAside()

        /// <summary>
        /// A file that cannot be read is put aside and said; the store starts empty, and is learned again.
        /// </summary>
        [Test]
        public void AnUnreadableFile_IsPutAside()
        {

            System.IO.File.WriteAllText(File, "{ \"localControllers\": [ { broken");

            var said   = new List<String>();
            var store  = new KeyPinStore(File);

            store.OnNotice += (level, message) => said.Add(message);
            store.Load();

            Assert.Multiple(() => {
                Assert.That(store.All,                               Is.Empty);
                Assert.That(System.IO.File.Exists(File + ".unreadable"), Is.True, "the unreadable file was not put aside");
                Assert.That(said,                                    Has.Some.Contains("could not be read"));
            });

        }

        #endregion

        #region TheRoutesToTheStations_ArePutBack_AtTheStart()

        /// <summary>
        /// A station behind a controller does not boot again because its CSMS did: the routes to the stations
        /// of the store are put back when the CSMS is built, through their controllers.
        /// </summary>
        [Test]
        public async Task TheRoutesToTheStations_ArePutBack_AtTheStart()
        {

            var store = new KeyPinStore(File);

            store.NoteStation("cs001", "lc001", At);
            store.NoteStation("cs002", "lc001", At);

            var csms = TestCSMSs.New(directory, TestCSMSs.Offline);

            try
            {

                Assert.Multiple(() => {

                    foreach (var station in new[] { "cs001", "cs002" })
                    {
                        Assert.That(csms.Node.Routing.LookupNetworkingNode(NetworkingNode_Id.Parse(station), out var reachability), Is.True, $"no route to {station}");
                        Assert.That(reachability?.NetworkingHub?.ToString(), Is.EqualTo("lc001"), $"the route to {station} does not go through its controller");
                    }

                    Assert.That(csms.KeyPins.LocalControllerOf("cs002"), Is.EqualTo("lc001"));

                });

            }
            finally
            {
                await csms.DisposeAsync();
            }

        }

        #endregion

    }

}
