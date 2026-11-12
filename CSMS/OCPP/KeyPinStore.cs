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

using System.Globalization;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.CSMS.Web;

#endregion

namespace cloud.charging.open.CSMS.OCPP
{

    /// <summary>
    /// A charging station behind a Local Controller, and the pin set this CSMS last handed it for its endpoint to
    /// that controller.
    /// </summary>
    /// <param name="Station">The charging station, by its identity.</param>
    /// <param name="Noted">Since when it is known to be behind its controller: its BootNotification came through it.</param>
    /// <param name="Connection">The instance of TLSClientController that is its endpoint to the controller, once it is known.</param>
    /// <param name="Version">The version of the pin set last sent - or, before one was, the version the station reported holding.</param>
    /// <param name="Pins">The key pins of the pin set last sent, in hexadecimal.</param>
    /// <param name="Sent">When it was sent.</param>
    /// <param name="Answer">What the station answered: "Accepted", or what it refused with and why - or why it could not be asked.</param>
    /// <param name="Accepted">Whether it took the pin set.</param>
    public sealed record StationPinSet(String                 Station,
                                       DateTimeOffset         Noted,
                                       String?                Connection   = null,
                                       UInt64?                Version      = null,
                                       IReadOnlyList<String>? Pins         = null,
                                       DateTimeOffset?        Sent         = null,
                                       String?                Answer       = null,
                                       Boolean                Accepted     = false)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("station",     Station),
                   new JProperty("noted",       Noted.ToUniversalTime().ToString("o")),
                   new JProperty("connection",  Connection),
                   new JProperty("version",     Version),
                   new JProperty("pins",        new JArray(Pins ?? [])),
                   new JProperty("sent",        Sent?.ToUniversalTime().ToString("o")),
                   new JProperty("answer",      Answer),
                   new JProperty("accepted",    Accepted)
               );

        public static StationPinSet? TryParse(JToken JSON)
        {
            try
            {

                var station = JSON["station"]?.Value<String>();

                if (String.IsNullOrEmpty(station) || JSON["noted"]?.Type != JTokenType.String)
                    return null;

                return new StationPinSet(
                           station,
                           KeyPinStore.ParseTime(JSON["noted"]) ?? DateTimeOffset.UnixEpoch,
                           JSON["connection"]?.Type == JTokenType.String ? JSON["connection"]!.Value<String>() : null,
                           JSON["version"]?.   Type == JTokenType.Integer ? JSON["version"]!.Value<UInt64>() : null,
                           [.. (JSON["pins"] as JArray ?? []).Where(pin => pin.Type == JTokenType.String).Select(pin => pin.Value<String>()!)],
                           KeyPinStore.ParseTime(JSON["sent"]),
                           JSON["answer"]?.    Type == JTokenType.String ? JSON["answer"]!.Value<String>() : null,
                           JSON["accepted"]?.  Type == JTokenType.Boolean && JSON["accepted"]!.Value<Boolean>()
                       );

            }
            catch (Exception e) when (e is FormatException or InvalidCastException or ArgumentException or OverflowException)
            {
                return null;
            }
        }

    }


    /// <summary>
    /// A Local Controller this CSMS knows charging stations behind, the key pins it last read of it, and those
    /// stations.
    /// </summary>
    /// <param name="LocalController">The Local Controller, by its identity at this CSMS.</param>
    /// <param name="CurrentKeyPin">The key pin of the key its station port presents now, as last read: EVQICtrlr[TLSServer].ActiveKeyPin.</param>
    /// <param name="NextKeyPin">The key pin of the next key it announced, as last read; null for none.</param>
    /// <param name="KeyCreated">When its current key was made, as last read.</param>
    /// <param name="Read">When the pins were last read; null where they never were.</param>
    /// <param name="Stations">The charging stations behind it.</param>
    public sealed record LocalControllerKeyPins(String                        LocalController,
                                                String?                       CurrentKeyPin   = null,
                                                String?                       NextKeyPin      = null,
                                                DateTimeOffset?               KeyCreated      = null,
                                                DateTimeOffset?               Read            = null,
                                                IReadOnlyList<StationPinSet>? Stations        = null)
    {

        /// <summary>
        /// The key pins a station behind it is to hold: the current key's, and the next key's where one is
        /// announced - the current one first.
        /// </summary>
        public IReadOnlyList<String> Pins

            => [.. new[] { CurrentKeyPin, NextKeyPin }.OfType<String>()];

        public JObject ToJSON()

            => new (
                   new JProperty("localController",  LocalController),
                   new JProperty("currentKeyPin",    CurrentKeyPin),
                   new JProperty("nextKeyPin",       NextKeyPin),
                   new JProperty("keyCreated",       KeyCreated?.ToUniversalTime().ToString("o")),
                   new JProperty("read",             Read?.ToUniversalTime().ToString("o")),
                   new JProperty("stations",         new JArray((Stations ?? []).Select(station => station.ToJSON())))
               );

        public static LocalControllerKeyPins? TryParse(JToken JSON)
        {
            try
            {

                var localController = JSON["localController"]?.Value<String>();

                if (String.IsNullOrEmpty(localController))
                    return null;

                return new LocalControllerKeyPins(
                           localController,
                           JSON["currentKeyPin"]?.Type == JTokenType.String ? JSON["currentKeyPin"]!.Value<String>() : null,
                           JSON["nextKeyPin"]?.   Type == JTokenType.String ? JSON["nextKeyPin"]!.   Value<String>() : null,
                           KeyPinStore.ParseTime(JSON["keyCreated"]),
                           KeyPinStore.ParseTime(JSON["read"]),
                           [.. (JSON["stations"] as JArray ?? []).Select(StationPinSet.TryParse).OfType<StationPinSet>()]
                       );

            }
            catch (Exception e) when (e is FormatException or InvalidCastException or ArgumentException)
            {
                return null;
            }
        }

    }


    /// <summary>
    /// The key pins this CSMS hands the charging stations behind its Local Controllers (white paper "Key Pins
    /// and TLS 1.3 Raw Public Keys for Local Controllers", sections 5.5 to 5.7): per Local Controller the pins
    /// it last read of it, and per station behind it the endpoint the pins are for and the pin set it was last
    /// sent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Its own file, beside the configuration file.</b> Which stations are behind which controller is what
    /// a rollover sends its pin sets to, and the routes the OCPP node learns from their BootNotifications are
    /// gone with a restart: a station behind a controller does not boot again because its CSMS did. It holds
    /// no secret - identities, key pins and versions - and is written for its owner all the same, as
    /// everything beside it is.
    /// </para>
    /// <para>
    /// <b>A file that cannot be read is put aside</b>, and not a reason to stop: what it forgot is learned
    /// again as the stations boot, and the versions a station holds are read from it before every pin set.
    /// </para>
    /// <para>
    /// <b>One controller per station.</b> A station whose BootNotification comes through another controller,
    /// or straight to this CSMS, has moved: it is taken off the controller it was behind.
    /// </para>
    /// </remarks>
    public sealed class KeyPinStore
    {

        #region Data

        /// <summary>
        /// The name of the file beside the configuration file.
        /// </summary>
        public const String  DefaultFileName  = "ocpp-key-pins.json";

        private readonly Dictionary<String, LocalControllerKeyPins>  controllers  = new (StringComparer.Ordinal);

        private readonly Object  updateLock  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Where it is kept.
        /// </summary>
        public String  Path    { get; }

        /// <summary>
        /// Every Local Controller known, with the stations behind it, by identity.
        /// </summary>
        public IReadOnlyList<LocalControllerKeyPins> All
        {
            get
            {
                lock (updateLock)
                {
                    return [.. controllers.Values.OrderBy(controller => controller.LocalController, StringComparer.OrdinalIgnoreCase)];
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
        /// The key pins in the given file; it need not exist yet.
        /// </summary>
        public KeyPinStore(String? Path = null)
        {
            this.Path = System.IO.Path.GetFullPath(Path ?? DefaultFileName);
        }

        #endregion


        #region Load()

        /// <summary>
        /// Read the file, where there is one; one that cannot be read is moved aside, said so, and started over.
        /// </summary>
        public void Load()
        {

            lock (updateLock)
            {

                controllers.Clear();

                if (!File.Exists(Path))
                    return;

                try
                {

                    var text = File.ReadAllText(Path);

                    if (String.IsNullOrWhiteSpace(text))
                        return;

                    using var reader = new JsonTextReader(new StringReader(text)) { DateParseHandling = DateParseHandling.None };

                    foreach (var entry in JObject.Load(reader)["localControllers"] as JArray ?? [])
                        if (LocalControllerKeyPins.TryParse(entry) is LocalControllerKeyPins controller)
                            controllers[controller.LocalController] = controller;

                }
                catch (Exception e)
                {

                    var aside = Path + ".unreadable";

                    try
                    {
                        File.Move(Path, aside, overwrite: true);
                    }
                    catch (Exception)
                    { }

                    controllers.Clear();

                    OnNotice?.Invoke(LogLevel.Warning,
                                     $"'{Path}' could not be read, and was put aside as '{aside}': {e.Message} " +
                                     "The charging stations behind the local controllers are learned again as they boot.");

                }

            }

        }

        #endregion

        #region Get(LocalController) / LocalControllerOf(Station) / StationOf(Station)

        /// <summary>
        /// The Local Controller of the given identity, as last noted - or null.
        /// </summary>
        public LocalControllerKeyPins? Get(String LocalController)
        {
            lock (updateLock)
            {
                return controllers.TryGetValue(LocalController, out var controller) ? controller : null;
            }
        }

        /// <summary>
        /// The Local Controller the given station is behind - or null.
        /// </summary>
        public String? LocalControllerOf(String Station)
        {
            lock (updateLock)
            {
                return controllers.Values.FirstOrDefault(controller => (controller.Stations ?? []).Any(station => station.Station == Station))?.LocalController;
            }
        }

        /// <summary>
        /// The given station, as last noted - or null.
        /// </summary>
        public StationPinSet? StationOf(String Station)
        {
            lock (updateLock)
            {
                return controllers.Values.SelectMany(controller => controller.Stations ?? []).FirstOrDefault(station => station.Station == Station);
            }
        }

        #endregion

        #region NoteStation(Station, LocalController, At)

        /// <summary>
        /// A charging station is behind the given Local Controller: its BootNotification came through it. Taken
        /// off any other controller it was behind.
        /// </summary>
        /// <returns>Whether that is news: it was not known behind this controller.</returns>
        public Boolean NoteStation(String          Station,
                                   String          LocalController,
                                   DateTimeOffset  At)
        {

            lock (updateLock)
            {

                if (controllers.TryGetValue(LocalController, out var known) &&
                    (known.Stations ?? []).Any(station => station.Station == Station))
                {
                    return false;
                }

                TakeOff(Station, LocalController);

                known ??= new LocalControllerKeyPins(LocalController, Stations: []);

                controllers[LocalController] = known with {
                                                   Stations = [.. (known.Stations ?? []).Append(new StationPinSet(Station, At)).
                                                                                       OrderBy(station => station.Station, StringComparer.OrdinalIgnoreCase)]
                                               };

                Save();
                return true;

            }

        }

        #endregion

        #region ForgetStation(Station)

        /// <summary>
        /// The given station is behind no Local Controller (any more): it came straight to this CSMS.
        /// </summary>
        /// <returns>Whether it was known behind one.</returns>
        public Boolean ForgetStation(String Station)
        {

            lock (updateLock)
            {

                if (!TakeOff(Station, null))
                    return false;

                Save();
                return true;

            }

        }

        #endregion

        #region NotePins(LocalController, CurrentKeyPin, NextKeyPin, KeyCreated, At)

        /// <summary>
        /// The key pins read of a Local Controller.
        /// </summary>
        public void NotePins(String           LocalController,
                             String?          CurrentKeyPin,
                             String?          NextKeyPin,
                             DateTimeOffset?  KeyCreated,
                             DateTimeOffset   At)
        {

            lock (updateLock)
            {

                controllers[LocalController] = (controllers.TryGetValue(LocalController, out var known)
                                                    ? known
                                                    : new LocalControllerKeyPins(LocalController, Stations: [])) with {
                                                   CurrentKeyPin  = CurrentKeyPin,
                                                   NextKeyPin     = NextKeyPin,
                                                   KeyCreated     = KeyCreated,
                                                   Read           = At
                                               };

                Save();

            }

        }

        #endregion

        #region NoteConnection(Station, Connection, Version)

        /// <summary>
        /// Which endpoint of a station leads to its Local Controller, and the version of the pin set it holds
        /// there: what its report said.
        /// </summary>
        public void NoteConnection(String  Station,
                                   String  Connection,
                                   UInt64  Version)
        {

            lock (updateLock)
            {

                // The version it holds, until one is sent: then the one sent,
                // and whether it was taken, is what is kept.
                if (Update(Station, station => station with {
                                                   Connection  = Connection,
                                                   Version     = station.Sent is null || station.Connection != Connection
                                                                     ? Version
                                                                     : station.Version
                                               }))
                {
                    Save();
                }

            }

        }

        #endregion

        #region NoteSent(Station, Connection, Version, Pins, At, Answer, Accepted)

        /// <summary>
        /// A pin set sent to a station, and what it answered.
        /// </summary>
        public void NoteSent(String                Station,
                             String                Connection,
                             UInt64                Version,
                             IEnumerable<String>   Pins,
                             DateTimeOffset        At,
                             String                Answer,
                             Boolean               Accepted)
        {

            lock (updateLock)
            {

                if (Update(Station, station => station with {
                                                   Connection  = Connection,
                                                   Version     = Version,
                                                   Pins        = [.. Pins],
                                                   Sent        = At,
                                                   Answer      = Answer,
                                                   Accepted    = Accepted
                                               }))
                {
                    Save();
                }

            }

        }

        #endregion


        #region (internal static) ParseTime(JSON)

        internal static DateTimeOffset? ParseTime(JToken? JSON)

            => JSON?.Type == JTokenType.String &&
               DateTimeOffset.TryParse(JSON.Value<String>(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time)
                   ? time
                   : null;

        #endregion

        #region (private) TakeOff(Station, Except) / Update(Station, Change)

        /// <summary>
        /// Take the station off every controller but the given one. Under the lock.
        /// </summary>
        private Boolean TakeOff(String   Station,
                                String?  Except)
        {

            var taken = false;

            foreach (var controller in controllers.Values.ToArray())
            {

                if (controller.LocalController == Except || !(controller.Stations ?? []).Any(station => station.Station == Station))
                    continue;

                controllers[controller.LocalController] = controller with {
                                                              Stations = [.. (controller.Stations ?? []).Where(station => station.Station != Station)]
                                                          };

                taken = true;

            }

            return taken;

        }

        /// <summary>
        /// Change the record of a station, where it is known. Under the lock.
        /// </summary>
        private Boolean Update(String                               Station,
                               Func<StationPinSet, StationPinSet>  Change)
        {

            foreach (var controller in controllers.Values.ToArray())
            {

                var stations = controller.Stations ?? [];

                if (stations.FirstOrDefault(station => station.Station == Station) is not StationPinSet known)
                    continue;

                controllers[controller.LocalController] = controller with {
                                                              Stations = [.. stations.Select(station => station.Station == Station ? Change(known) : station)]
                                                          };

                return true;

            }

            return false;

        }

        #endregion

        #region (private) Save()

        /// <summary>
        /// Written whole, to a file beside it first and moved over it; what cannot be written is said, and kept
        /// in memory all the same.
        /// </summary>
        private void Save()
        {

            try
            {

                var directory = System.IO.Path.GetDirectoryName(Path);

                if (!String.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);

                var temporary = Path + ".tmp";

                OwnerOnlyFile.Write(
                    temporary,
                    new JObject(
                        new JProperty("localControllers", new JArray(
                            controllers.Values.OrderBy(controller => controller.LocalController, StringComparer.OrdinalIgnoreCase).
                                               Select (controller => controller.ToJSON())
                        ))
                    ).ToString(Formatting.Indented) + Environment.NewLine,
                    problem => OnNotice?.Invoke(LogLevel.Warning, problem)
                );

                File.Move(temporary, Path, overwrite: true);

            }
            catch (Exception e)
            {
                OnNotice?.Invoke(LogLevel.Warning, $"'{Path}' could not be written: {e.Message}");
            }

        }

        #endregion

    }

}
