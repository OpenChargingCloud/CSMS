/*
 * Copyright (c) 2014-2020 GraphDefined GmbH
 * This file is part of WWCP OCPP <https://github.com/OpenChargingCloud/WWCP_OCPP>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using OCPPv1_6   = cloud.charging.open.protocols.OCPPv1_6;
using OCPPv2_0_1 = cloud.charging.open.protocols.OCPPv2_0_1;
using OCPPv2_1   = cloud.charging.open.protocols.OCPPv2_1;

#endregion

namespace org.GraphDefined.WWCP.OCPP.Tests
{

    public class Program
    {

        /// <summary>
        /// A runner for running all versions of the OCPP test runners.
        /// </summary>
        /// <param name="Arguments">Command line arguments</param>
        public static async Task Main(String[] Arguments)
        {

            var ByteArray = new Byte[] {
                1,
                254,
                16,
                0,
                239,
                76,
                211,
                98
            };

            var payloadLength  = (UInt64) (ByteArray[1] & 0x7f);
            var offset         = 2U;

            if (payloadLength == 126) {

                payloadLength  = (UInt64) ((ByteArray[2] << 8) | ByteArray[3]);

                offset         = 4U;

            }

            else if (payloadLength == 127) {

                payloadLength  = ((UInt64) ByteArray[2] << 56) |
                                 ((UInt64) ByteArray[3] << 48) |
                                 ((UInt64) ByteArray[4] << 40) |
                                 ((UInt64) ByteArray[5] << 32) |
                                 ((UInt64) ByteArray[6] << 24) |
                                 ((UInt64) ByteArray[7] << 16) |
                                 ((UInt64) ByteArray[8] <<  8) |
                                           ByteArray[9];

                offset         = 10U;

            }




            var ss = 23;


            #region Debug to Console/file

            var DebugFile = new TextWriterTraceListener("debug.log");

            var DebugTargets = new TextWriterTraceListener[] {
                DebugFile,
                new TextWriterTraceListener(Console.Out)
            };

            Trace.Listeners.AddRange(DebugTargets);

            #endregion

            #region Machine-dependent configuration

            //SMTPClient API_SMTPClient  = null;
            DNSClient  API_DNSClient   = null;

            switch (Environment.MachineName)
            {

                // Development...
                case "ZBOOK":
                case "ZBOOK2":
                case "ZBOOK3":
                case "OCTAL":
                case "OCCloud1A":
                case "OCCloud2A":
                case "OCCloud3A":

                    API_DNSClient = new DNSClient (SearchForIPv6DNSServers: false);

                    //API_SMTPClient  = new SMTPClient(RemoteHost:                 "mail.ahzf.de", //"159.69.66.88",
                    //                                 RemotePort:                 IPPort.Parse(25),
                    //                                 Login:                      "Primedic",
                    //                                 Password:                   "Xw0!pq4",
                    //                                 ValidateServerCertificate:  (TCPClient, Certificate, CertificateChain, PolicyErrors) => true,
                    //                                 DNSClient:                  API_DNSClient);

                    break;

                default:
                    throw new ApplicationException("It seems that your system is not prepared to run this software!");

            }

            Console.WriteLine("Found DNS servers: " + API_DNSClient.DNSServers.Select(v => v.ToString()).AggregateOrDefault((a, b) => a + ", " + b, String.Empty) + Environment.NewLine);

            #endregion


            Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "HTTPSSEs"));


            #region Setup CSMS v1.6

            // Support "gzip" and "deflate" HTTP compression

            var testCSMSv1_6           = new OCPPv1_6.TestCentralSystem(
                                             CentralSystemId:             OCPPv1_6.CentralSystem_Id.Parse("OCPPv1_6-Test01"),
                                             RequireAuthentication:       true,
                                             HTTPUploadPort:              IPPort.Parse(9901),
                                             DNSClient:                   API_DNSClient
                                         );

            var testBackendWebSockets  = testCSMSv1_6.CreateWebSocketService(
                                             TCPPort:                     IPPort.Parse(9900),
                                             //DisableWebSocketPings:       true,
                                             //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                                             AutoStart:                   true
                                         );

            //var TestBackendSOAP        = testCentralSystem.CreateSOAPService(
            //                                 TCPPort:    IPPort.Parse(8800),
            //                                 DNSClient:  API_DNSClient,
            //                                 AutoStart:  true
            //                             );

            //testCSMSv1_6.AddHTTPBasicAuth(OCPPv1_6.ChargeBox_Id.Parse("GD001"),         "1234");
            //testCentralSystem.AddHTTPBasicAuth(ChargeBox_Id.Parse("NLHLXELAAD002"), "minimumzestienkarakters");
            //testCentralSystem.AddHTTPBasicAuth(ChargeBox_Id.Parse("suby0200000328"), "plugXest20221110");
            //testCSMSv1_6.AddHTTPBasicAuth(OCPPv1_6.ChargeBox_Id.Parse("kostal_elaad_teststation"),  "plugXest20221110");
            testCSMSv1_6.AddHTTPBasicAuth(OCPPv1_6.ChargeBox_Id.Parse("EVlink_Eichrecht"), "test1234test1234");


            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnNewWebSocketConnection += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " new connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tNEW\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnTextMessageReceived     += async (timestamp, server, connection, eventTrackingId, requestMessage) => {
                DebugX.Log(String.Concat("Received a web socket TEXT message: '", requestMessage, "'!"));
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tIN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", requestMessage, Environment.NewLine));
                }
            };

            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnTextMessageSent        += async (timestamp, server, connection, eventTrackingId, requestMessage) => {
                DebugX.Log(String.Concat("Sent     a web socket TEXT message: '", requestMessage, "'!"));
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tOUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", requestMessage, Environment.NewLine));
                }
            };

            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnCloseMessageReceived += async (timestamp, server, connection, eventTrackingId, statusCode, reason) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " charge box ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ") closed web socket connection"));
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tCLOSE\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnTCPConnectionClosed += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " closed TCP connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tQUIT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };





            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnPingMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnPingMessageSent     += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping sent:     '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING OUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv1_6.CentralSystemServers.First() as WebSocketServer).OnPongMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Pong received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv1_6)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPONG IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            #endregion

            #region Setup CSMS v2.0.1

            var testCSMSv2_0_1         = new OCPPv2_0_1.TestCSMS(
                                             CSMSId:                      OCPPv2_0_1.CSMS_Id.Parse("OCPPv2.0.1-Test01"),
                                             RequireAuthentication:       true,
                                             HTTPUploadPort:              IPPort.Parse(9911),
                                             DNSClient:                   API_DNSClient
                                         );

            var testBackendWebSockets2 = testCSMSv2_0_1.CreateWebSocketService(
                                             TCPPort:                     IPPort.Parse(9910),
                                             DisableWebSocketPings:       true,
                                             //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                                             AutoStart:                   true
                                         );

            testCSMSv2_0_1.AddHTTPBasicAuth(OCPPv2_0_1.ChargeBox_Id.Parse("cp001"), "DEADBEEFDEADBEEF");




            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnNewWebSocketConnection += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " new connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tNEW\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnTextMessageReceived     += async (timestamp, server, connection, eventTrackingId, requestMessage) => {
                DebugX.Log(String.Concat("Received a web socket TEXT message: '", requestMessage, "'!"));
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tIN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", requestMessage, Environment.NewLine));
                }
            };

            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnTextMessageSent        += async (timestamp, server, connection, eventTrackingId, requestMessage) => {
                DebugX.Log(String.Concat("Sent     a web socket TEXT message: '", requestMessage, "'!"));
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tOUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", requestMessage, Environment.NewLine));
                }
            };

            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnCloseMessageReceived += async (timestamp, server, connection, eventTrackingId, statusCode, reason) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " charge box ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ") closed web socket connection"));
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tCLOSE\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnTCPConnectionClosed += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " closed TCP connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tQUIT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };





            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnPingMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnPingMessageSent     += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping sent:     '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING OUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_0_1.CSMSServers.First() as WebSocketServer).OnPongMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Pong received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv2_0_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPONG IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            #endregion

            #region Setup CSMS v2.1

            var testCSMSv2_1               = new OCPPv2_1.TestCSMS(
                                                 Id:                          OCPPv2_1.CSMS_Id.Parse("OCPPv2.1-Test01"),
                                                 RequireAuthentication:       false,
                                                 HTTPUploadPort:              IPPort.Parse(9921),
                                                 DNSClient:                   API_DNSClient
                                             );

            var testBackendWebSocketsv2_1  = testCSMSv2_1.CreateWebSocketService(
                                                 TCPPort:                     IPPort.Parse(9920),
                                                 DisableWebSocketPings:       true,
                                                 //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                                                 AutoStart:                   true
                                             );

            testCSMSv2_1.AddOrUpdateHTTPBasicAuth(OCPPv2_1.ChargeBox_Id.Parse("GD001"), "test123");




            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnNewWebSocketConnection += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " new connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tNEW\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnTextMessageReceived += async (timestamp, server, connection, eventTrackingId, requestMessage) => {
                DebugX.Log(String.Concat("Received a web socket TEXT message: '", requestMessage, "'!"));
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tIN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", requestMessage, Environment.NewLine));
                }
            };

            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnTextMessageSent += async (timestamp, server, connection, eventTrackingId, requestMessage) => {
                DebugX.Log(String.Concat("Sent     a web socket TEXT message: '", requestMessage, "'!"));
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tOUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", requestMessage, Environment.NewLine));
                }
            };

            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnCloseMessageReceived += async (timestamp, server, connection, eventTrackingId, statusCode, reason) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " charge box ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ") closed web socket connection"));
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tCLOSE\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnTCPConnectionClosed += async (timestamp, server, connection, reason, eventTrackingId) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " closed TCP connection with ", connection.TryGetCustomData("chargeBoxId") + $", reason: {reason} " + " (" + connection.RemoteSocket + ")"));
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tQUIT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };





            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnPingMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnPingMessageSent += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping sent:     '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING OUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnPongMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
                DebugX.Log(nameof(WebSocketServer) + ": Pong received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCSMSv2_1)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPONG IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            #endregion


            // http://127.0.0.1:3502/chargeBoxes

            //var chargingStation1  = new TestChargePoint(
            //                            ChargeBoxId:              OCPPv1_6.ChargeBox_Id.Parse("GD001"),
            //                            ChargePointVendor:        "GraphDefined",
            //                            ChargePointModel:         "VCP.1",
            //                            NumberOfConnectors:       2,

            //                            Description:              I18NString.Create(Languages.en, "Our first virtual charging station!"),
            //                            ChargePointSerialNumber:  "SN-CP0001",
            //                            ChargeBoxSerialNumber:    "SN-CB0001",
            //                            FirmwareVersion:          "v0.1",
            //                            Iccid:                    "0000",
            //                            IMSI:                     "1111",
            //                            MeterType:                "Virtual Energy Meter",
            //                            MeterSerialNumber:        "SN-EN0001",
            //                            MeterPublicKey:           "0xcafebabe",

            //                            //DisableSendHeartbeats:    true,

            //                            //HTTPBasicAuth:            new Tuple<String, String>("OLI_001", "1234"),
            //                            //HTTPBasicAuth:            new Tuple<String, String>("GD001", "1234"),
            //                            DNSClient:                API_DNSClient
            //                        );

            //var chargingStation2  = new TestChargePoint(
            //                            ChargeBoxId:              OCPPv1_6.ChargeBox_Id.Parse("CP002"),
            //                            ChargePointVendor:        "GraphDefined",
            //                            ChargePointModel:         "VCP.2",
            //                            NumberOfConnectors:       2,

            //                            Description:              I18NString.Create(Languages.en, "Our 2nd virtual charging station!"),
            //                            ChargePointSerialNumber:  "SN-CP0002",
            //                            ChargeBoxSerialNumber:    "SN-CB0002",
            //                            FirmwareVersion:          "v0.1",
            //                            Iccid:                    "3333",
            //                            IMSI:                     "4444",
            //                            MeterType:                "Virtual Energy Meter",
            //                            MeterSerialNumber:        "SN-EN0002",
            //                            MeterPublicKey:           "0xbabecafe",

            //                            DNSClient:                API_DNSClient
            //                        );


            //var response1  =  await chargingStation1.ConnectWebSocket("From:GD001",
            //                                                          "To:OCPPTest01",
            //                                                          //URL.Parse("ws://janus1.graphdefined.com:80/"));
            //                                                          URL.Parse("http://127.0.0.1:9900/" + chargingStation1.ChargeBoxId),
            //                                                          DisableWebSocketPings:       true
            //                                                          //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10)
            //                                                          );
            //                                                          //URL.Parse("http://oca.charging.cloud:9900/" + chargingStation1.ChargeBoxId));
            //                                                          //URL.Parse("ws://oca.charging.cloud/io/OCPPv1.6j/" + chargingStation1.ChargeBoxId));
            //                                                          //URL.Parse("wss://oca.charging.cloud/io/OCPPv1.6j/" + chargingStation1.ChargeBoxId));
            //                                                          //URL.Parse("ws://35.190.199.146:8080/stationServer/websocket/OLI_001"));
            //
            //                                                          //URL.Parse("wss://encharge-broker-ppe1.envisioniot.com/ocpp-broker/ocpp/" + chargingStation1.ChargeBoxId));      // Envisison
            //                                                          //URL.Parse("wss://testop.amplified.cloud/ocpp16/GDEF"));                                                         // Stackbox GmbH
            //                                                          //URL.Parse("wss://ocpp.eu.ngrok.io/GD001"));                                                                     // Monta
            //                                                          //URL.Parse("wss://cpc.demo.dev.charge.ampeco.tech:443/test/GD001"));                                             // AMPECO
            //                                                          //URL.Parse("ws://ocppj.yaayum.com:8887/CUS002"));                                                                // yaayum
            //                                                          //URL.Parse("ws://ocpp-dev.eastus.azurecontainer.io:8433/VENTURUS/GD001"));

            //await Task.Delay(250);

            //var response01a  = await chargingStation1.SendBootNotification();
            //var response02a  = await chargingStation1.SendHeartbeat();
            //var response03a  = await chargingStation1.Authorize(IdToken.Parse("aabbccdd"));
            //var response03b  = await chargingStation1.Authorize(IdToken.Parse("000000"));
            //var response04a  = await chargingStation1.SendStatusNotification(Connector_Id.Parse(1), ChargePointStatus.Available, ChargePointErrorCodes.NoError, "info 1", Timestamp.Now, "GD", "VEC01");
            //var response05a  = await chargingStation1.TransferData("GD", "Message1", "Data1");
            //var response06a  = await chargingStation1.SendDiagnosticsStatusNotification(DiagnosticsStatus.UploadFailed);
            //var response07a  = await chargingStation1.SendFirmwareStatusNotification(FirmwareStatus.Installed);


            //var response21a  = await testCentralSystem.Reset(chargingStation1.ChargeBoxId, ResetTypes.Soft);
            //var response22a  = await testCentralSystem.Reset(chargingStation1.ChargeBoxId, ResetTypes.Hard);

            var xx = "y";


            #region OCPP v1.6 SOAP Tests

            //await chargingStation2.InitSOAP("From:CP002",
            //                                "To:OCPPTest01",
            //                                URL.Parse("http://127.0.0.1:8800/v1.6"),
            //                                HTTPContentType: HTTPContentType.XMLTEXT_UTF8);

            //var response2a = await chargingStation2.SendBootNotification();
            //var response2b = await chargingStation2.SendHeartbeat();


            //var response3a = await testCentralSystem.Reset                 (chargingStation1.ChargeBoxId, ResetTypes.Hard);
            //DebugX.Log("Reset: "              + response3a.Status.ToString());

            //var response3d = await testCentralSystem.ChangeAvailability    (chargingStation1.ChargeBoxId, Connector_Id.Parse(1), Availabilities.Operative);
            //DebugX.Log("ChangeAvailability: " + response3d.Status.ToString());

            //var response3e1 = await testCentralSystem.GetConfiguration      (chargingStation1.ChargeBoxId);
            //DebugX.Log("GetConfiguration: "   + response3e1.ConfigurationKeys.Select(ckey => ckey.ToJSON().ToString()).AggregateWith(Environment.NewLine));

            //var response3e2 = await testCentralSystem.GetConfiguration      (chargingStation1.ChargeBoxId, new String[] { "name" });
            //DebugX.Log("GetConfiguration: "   + response3e2.ConfigurationKeys.Select(ckey => ckey.ToJSON().ToString()).AggregateWith(Environment.NewLine));

            //var response3f1 = await testCentralSystem.ChangeConfiguration   (chargingStation1.ChargeBoxId, "doNotChangeMe", "1234");
            //DebugX.Log("ChangeConfiguration: " + response3f1.Status.ToString());

            //var response3f2 = await testCentralSystem.ChangeConfiguration   (chargingStation1.ChargeBoxId, "name", "1234");
            //DebugX.Log("ChangeConfiguration: " + response3f2.Status.ToString());

            //var response3e2 = await testCentralSystem.GetConfiguration(chargingStation1.ChargeBoxId);
            //DebugX.Log("GetConfiguration: " + response3e2.ConfigurationKeys.Select(ckey => ckey.ToJSON().ToString()).AggregateWith(Environment.NewLine));

            //var response3g1 = await testCentralSystem.DataTransfer          (chargingStation1.ChargeBoxId, "vendor", "MessageId", "Data");
            //DebugX.Log("DataTransfer: " + response3g1.Status.ToString() + ": " + response3g1.Data);

            //var response3g2 = await testCentralSystem.DataTransfer(chargingStation1.ChargeBoxId, "GraphDefined", "Hello", "World!");
            //DebugX.Log("DataTransfer: " + response3g2.Status.ToString() + ": " + response3g2.Data);

            //var response3h = await testCentralSystem.GetDiagnostics        (chargingStation1.ChargeBoxId, "Location", Timestamp.Now - TimeSpan.FromMinutes(30), Timestamp.Now - TimeSpan.FromMinutes(15), 3, TimeSpan.FromSeconds(30));
            //var response3i = await testCentralSystem.TriggerMessage        (chargingStation1.ChargeBoxId, MessageTriggers.MeterValues, Connector_Id.Parse(1));
            //var response3j = await testCentralSystem.UpdateFirmware        (chargingStation1.ChargeBoxId, "Location", Timestamp.Now, 3, TimeSpan.FromSeconds(30));

            //var response3k = await testCentralSystem.ReserveNow            (chargingStation1.ChargeBoxId, Connector_Id.Parse(1), Reservation_Id.Parse("1234"), Timestamp.Now + TimeSpan.FromMinutes(15), IdToken.Parse("1234"));
            //var response3l = await testCentralSystem.CancelReservation     (chargingStation1.ChargeBoxId, Reservation_Id.Parse("1234"));

            //var response3m = await testCentralSystem.RemoteStartTransaction(chargingStation1.ChargeBoxId, IdToken.Parse("1234"), Connector_Id.Parse(1), null);
            //DebugX.Log("RemoteStartTransaction: " + response3m.Status.ToString());

            //await Task.Delay(5000);

            //var transactionId = testCentralSystem.TransactionIds[response3m.Request.ChargeBoxId + "*" + response3m.Request.ConnectorId.ToString()];

            //var response3n = await testCentralSystem.RemoteStopTransaction (chargingStation1.ChargeBoxId, transactionId);
            //DebugX.Log("RemoteStopTransaction: " + response3n.Status.ToString());

            //var response3o = await testCentralSystem.SetChargingProfile    (chargingStation1.ChargeBoxId, Connector_Id.Parse(1), null);
            //var response3p = await testCentralSystem.ClearChargingProfile  (chargingStation1.ChargeBoxId, null, Connector_Id.Parse(1), null, null);
            //var response3q = await testCentralSystem.GetCompositeSchedule  (chargingStation1.ChargeBoxId, Connector_Id.Parse(1), TimeSpan.FromMinutes(15), null);
            //var response3r = await testCentralSystem.UnlockConnector       (chargingStation1.ChargeBoxId, Connector_Id.Parse(1));

            //var response3s = await testCentralSystem.GetLocalListVersion   (chargingStation1.ChargeBoxId);
            //var response3t = await testCentralSystem.SendLocalList         (chargingStation1.ChargeBoxId, 1, UpdateTypes.Full, null);
            //var response3u = await testCentralSystem.ClearCache            (chargingStation1.ChargeBoxId);


            //var ChargingStation1  = new ChargePointSOAPServer(TCPPort:    IPPort.Parse(8801),
            //                                                  DNSClient:  API_DNSClient,
            //                                                  AutoStart:  true);

            //var ChargingStation2  = new ChargePointSOAPServer(TCPPort:    IPPort.Parse(8802),
            //                                                  DNSClient:  API_DNSClient,
            //                                                  AutoStart:  true);

            //var ChargingStation3  = new ChargePointSOAPServer(TCPPort:    IPPort.Parse(8802),
            //                                                  DNSClient:  API_DNSClient,
            //                                                  AutoStart:  true);


            //var OCPPClient1 = new CentralSystemSOAPClient(ChargeBoxIdentity:           ChargeBox_Id.Parse("1"),
            //                                              From:                        "https://1.1.1.1:" + SOAPServer.      IPPorts.First() + SOAPServer.URLPrefix,
            //                                              To:                          "https://2.2.2.2:" + ChargingStation1.IPPorts.First() + ChargingStation1.URLPrefix,

            //                                              RemoteURL:                   URL.Parse("http://localhost:" + ChargingStation1.IPPorts.First() + ChargingStation1.URLPrefix),
            //                                              VirtualHostname:             null,
            //                                              Description:                 null,
            //                                              RemoteCertificateValidator:  null,
            //                                              ClientCertificateSelector:   null,
            //                                              ClientCert:                  null,
            //                                              HTTPUserAgent:               null,
            //                                              URLPathPrefix:               HTTPPath.Parse("/v1.6"),
            //                                              WSSLoginPassword:            null,
            //                                              RequestTimeout:              TimeSpan.FromSeconds(25),
            //                                              TransmissionRetryDelay:      null,
            //                                              MaxNumberOfRetries:          3,
            //                                              UseHTTPPipelining:           false,
            //                                              LoggingContext:              null,
            //                                              LogfileCreator:              null,
            //                                              HTTPLogger:                  null,
            //                                              DNSClient:                   API_DNSClient);

            //var rs_response = await OCPPClient1.RemoteStartTransaction(//ChargeBoxIdentity:  ChargeBox_Id.Parse("1"),
            //                                                           IdTag:              IdToken.Parse("11223344"),
            //                                                           ConnectorId:        Connector_Id.Parse("1"),
            //                                                           ChargingProfile:    new ChargingProfile(
            //                                                                                   ChargingProfile_Id.Parse("1"),
            //                                                                                   0,
            //                                                                                   ChargingProfilePurposes.TxProfile,
            //                                                                                   ChargingProfileKinds.Relative,
            //                                                                                   new ChargingSchedule(
            //                                                                                       ChargingRateUnits.Amperes,
            //                                                                                       new ChargingSchedulePeriod[] {
            //                                                                                           new ChargingSchedulePeriod(0, 20, 3)
            //                                                                                       }
            //                                                                                   ),
            //                                                                                   Transaction_Id.Parse("1234")
            //                                                                                   //RecurrencyKinds.Daily
            //                                                                               ));

            //var rs2 = rs_response.Content;

            #endregion


            #region DEBUG tasks after 10 seconds...

            if (Environment.MachineName == "QUADQUANTOR")
            {
                await Task.Factory.StartNew(async () => {

                    await Task.Delay(10000);

                });
            }

            #endregion

            Console.WriteLine();
            Console.WriteLine("finished...");

            #region Wait for key 'Q' pressed... and quit.

            var       chargeBoxId   = "";
            var       version       = 2;
            var       quit          = false;
            String[]? commandArray  = null;

            do
            {

                commandArray = Console.ReadLine()?.Trim()?.Split(' ');

                if (commandArray is not null &&
                    commandArray.Any())
                {

                    var command = commandArray[0]?.ToLower();

                    if (command is not null &&
                        command.Length > 0)
                    {

                        if (command == "q")
                            quit = true;

                        #region SetVersion 1 | 2

                        if (command == "SetVersion".ToLower() && commandArray.Length == 2)
                        {

                            if (commandArray[1] == "1" || commandArray[1] == "1.6"   || commandArray[1] == "v1.6")
                                version = 1;

                            if (commandArray[1] == "2" || commandArray[1] == "2.0.1" || commandArray[1] == "v2.0.1")
                                version = 2;

                            if (commandArray[1] == "2" || commandArray[1] == "2.1"   || commandArray[1] == "v2.1")
                                version = 2;

                        }

                        #endregion

                        #region Use chargeBoxId

                        if (command == "use".ToLower() && commandArray.Length == 2)
                        {

                            chargeBoxId = commandArray[1];

                            Console.WriteLine($"Now using charging station '{chargeBoxId}'!");

                        }

                        #endregion

                        #region AddHTTPBasicAuth

                        //   AddHTTPBasicAuth abcd1234
                        if (command == "AddHTTPBasicAuth".ToLower() && commandArray.Length == 2)
                        {
                            testCSMSv1_6.  AddHTTPBasicAuth        (OCPPv1_6.  ChargeBox_Id.Parse(chargeBoxId), commandArray[2]);
                            testCSMSv2_0_1.AddHTTPBasicAuth        (OCPPv2_0_1.ChargeBox_Id.Parse(chargeBoxId), commandArray[2]);
                            testCSMSv2_1.  AddOrUpdateHTTPBasicAuth(OCPPv2_1.  ChargeBox_Id.Parse(chargeBoxId), commandArray[2]);
                        }

                        #endregion


                        #region Reset

                        //   HardReset
                        if (command == "HardReset".ToLower() && commandArray.Length == 1)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.Reset(
                                                   ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   ResetType:    OCPPv1_6.ResetTypes.Hard
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.Reset(
                                                   new OCPPv2_1.CSMS.ResetRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       ResetType:     OCPPv2_1.ResetTypes.Immediate
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        //   SoftReset
                        if (command == "SoftReset".ToLower() && commandArray.Length == 1)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.Reset(
                                                   ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   ResetType:    OCPPv1_6.ResetTypes.Soft
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.Reset(
                                                   new OCPPv2_1.CSMS.ResetRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       ResetType:     OCPPv2_1.ResetTypes.OnIdle
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region UpdateFirmware

                        //   UpdateFirmware https://api2.ocpp.charging.cloud:9901/firmware.bin
                        if (command == "UpdateFirmware".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.UpdateFirmware(
                                               new OCPPv2_1.CSMS.UpdateFirmwareRequest(
                                                    ChargeBoxId:               OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                    Firmware:                  new OCPPv2_1.Firmware(
                                                                                   FirmwareURL:          URL.Parse(commandArray[1]),
                                                                                   RetrieveTimestamp:    Timestamp.Now,
                                                                                   InstallTimestamp:     Timestamp.Now,
                                                                                   SigningCertificate:   "xxx",
                                                                                   Signature:            "yyy"
                                                                               ),
                                                    UpdateFirmwareRequestId:   RandomExtensions.RandomInt32(),
                                                    Retries:                   3,
                                                    RetryInterval:             null
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SignedUpdateFirmware (OCPP v1.6)

                        //   SignedUpdateFirmware csrc
                        if (command == "SignedUpdateFirmware".ToLower() && commandArray.Length == 2 && commandArray[1].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCSMSv1_6.SignedUpdateFirmware(
                                               ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                               Firmware:          new OCPPv1_6.FirmwareImage(
                                                                      RemoteLocation:      URL.Parse("https://api2.ocpp.charging.cloud:9901/security0001.log"),
                                                                      RetrieveTimestamp:   Timestamp.Now,
                                                                      SigningCertificate:  "xxx",
                                                                      Signature:           "yyy"
                                                                  ),
                                               UpdateRequestId:   1,
                                               Retries:           null,
                                               RetryInterval:     null
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        // PublishFirmware

                        // UnpublishFirmware

                        #region GetBaseReport

                        //   GetBaseReport conf
                        //   GetBaseReport full
                        if (command == "GetBaseReport".ToLower() && (commandArray.Length == 1 || commandArray.Length == 2))
                        {

                            var response = await testCSMSv2_1.GetBaseReport(
                                               new OCPPv2_1.CSMS.GetBaseReportRequest(
                                                   ChargeBoxId:              OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetBaseReportRequestId:   RandomExtensions.RandomInt32(),
                                                   ReportBase:               commandArray[1] switch {
                                                                                 "conf"  => OCPPv2_1.ReportBases.ConfigurationInventory,
                                                                                 "full"  => OCPPv2_1.ReportBases.FullInventory,
                                                                                 _       => OCPPv2_1.ReportBases.SummaryInventory
                                                                             }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetReport

                        //   GetReport
                        if (command == "GetReport".ToLower() && (commandArray.Length == 1 || commandArray.Length == 2))
                        {

                            var response = await testCSMSv2_1.GetReport(
                                               new OCPPv2_1.CSMS.GetReportRequest(
                                                   ChargeBoxId:          OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetReportRequestId:   RandomExtensions.RandomInt32(),
                                                   ComponentCriteria:    new[] {
                                                                             OCPPv2_1.ComponentCriteria.Active
                                                                         },
                                                   ComponentVariables:   new[] {
                                                                             new OCPPv2_1.ComponentVariable(
                                                                                 Component:   new OCPPv2_1.Component(
                                                                                                  Name:       commandArray[1],
                                                                                                  Instance:   null,
                                                                                                  EVSE:       null
                                                                                              )
                                                                                 //Variable:    new OCPPv2_1.Variable(
                                                                                 //                 Name:       "",
                                                                                 //                 Instance:   null
                                                                                 //             )
                                                                             )
                                                                         }

                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetLog

                        if (command == "GetLog".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                //   getlog https://api2.ocpp.charging.cloud:9901 diagnostics
                                //   getlog https://api2.ocpp.charging.cloud:9901 security
                                var response = await testCSMSv1_6.GetLog(
                                                   ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   LogType:        commandArray[2].ToLower() switch {
                                                                        "security"  => OCPPv1_6.LogTypes.SecurityLog,
                                                                        _           => OCPPv1_6.LogTypes.DiagnosticsLog
                                                                   },
                                                   LogRequestId:   RandomExtensions.RandomInt32(),
                                                   Log:            new OCPPv1_6.LogParameters(
                                                                       RemoteLocation:    URL.Parse(commandArray[1]),
                                                                       OldestTimestamp:   null,
                                                                       LatestTimestamp:   null
                                                                   ),
                                                   Retries:        null,
                                                   RetryInterval:  null
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                //   getlog https://api2.ocpp.charging.cloud:9901 diagnostics
                                //   getlog https://api2.ocpp.charging.cloud:9901 security
                                //   getlog https://api2.ocpp.charging.cloud:9901 datacollector
                                var response = await testCSMSv2_1.GetLog(
                                                   new OCPPv2_1.CSMS.GetLogRequest(
                                                       ChargeBoxId:     OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       LogType:         commandArray[2].ToLower() switch {
                                                                             "security"       => OCPPv2_1.LogTypes.SecurityLog,
                                                                             "datacollector"  => OCPPv2_1.LogTypes.DataCollectorLog,
                                                                             _                => OCPPv2_1.LogTypes.DiagnosticsLog
                                                                        },
                                                       LogRequestId:    1,
                                                       Log:             new OCPPv2_1.LogParameters(
                                                                            RemoteLocation:    URL.Parse(commandArray[1]),
                                                                            OldestTimestamp:   null,
                                                                            LatestTimestamp:   null
                                                                        ),
                                                       Retries:         null,
                                                       RetryInterval:   null
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region SetVariables

                        //   SetVariables component variable value
                        if (command == "SetVariables".ToLower() && commandArray.Length == 4)
                        {

                            var response = await testCSMSv2_1.SetVariables(
                                               new OCPPv2_1.CSMS.SetVariablesRequest(
                                                   ChargeBoxId:    OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   VariableData:   new[] {
                                                                       new OCPPv2_1.SetVariableData(
                                                                           commandArray[3],
                                                                           new OCPPv2_1.Component(
                                                                               Name:       commandArray[1],
                                                                               Instance:   null,
                                                                               EVSE:       null
                                                                           ),
                                                                           new OCPPv2_1.Variable(
                                                                               Name:       commandArray[2],
                                                                               Instance:   null
                                                                           ),
                                                                           OCPPv2_1.AttributeTypes.Target
                                                                       )
                                                                   }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetVariables

                        //   GetVariables component variable
                        if (command == "GetVariables".ToLower() && commandArray.Length == 3)
                        {

                            var response = await testCSMSv2_1.GetVariables(
                                               new OCPPv2_1.CSMS.GetVariablesRequest(
                                                   ChargeBoxId:    OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   VariableData:   new[] {
                                                                       new OCPPv2_1.GetVariableData(
                                                                           new OCPPv2_1.Component(
                                                                               Name:       commandArray[1],
                                                                               Instance:   null,
                                                                               EVSE:       null
                                                                           ),
                                                                           new OCPPv2_1.Variable(
                                                                               Name:       commandArray[2],
                                                                               Instance:   null
                                                                           )
                                                                       )
                                                                   }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SetMonitoringBase

                        //   SetMonitoringBase
                        //   SetMonitoringBase factory
                        //   SetMonitoringBase hard
                        if (command == "SetMonitoringBase".ToLower() && (commandArray.Length == 1 || commandArray.Length == 2))
                        {

                            var response = await testCSMSv2_1.SetMonitoringBase(
                                               new OCPPv2_1.CSMS.SetMonitoringBaseRequest(
                                                   ChargeBoxId:      OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   MonitoringBase:   commandArray[1] switch {
                                                                         "factory"  => OCPPv2_1.MonitoringBases.FactoryDefault,
                                                                         "hard"     => OCPPv2_1.MonitoringBases.HardWiredOnly,
                                                                         _          => OCPPv2_1.MonitoringBases.All
                                                                     }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetMonitoringReport

                        //   GetMonitoringReport component [variable]
                        if (command == "GetMonitoringReport".ToLower() && (commandArray.Length == 2 || commandArray.Length == 3))
                        {

                            var response = await testCSMSv2_1.GetMonitoringReport(
                                               new OCPPv2_1.CSMS.GetMonitoringReportRequest(
                                                   ChargeBoxId:                    OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetMonitoringReportRequestId:   RandomExtensions.RandomInt32(),
                                                   MonitoringCriteria:             new[] {
                                                                                       OCPPv2_1.MonitoringCriteria.PeriodicMonitoring
                                                                                   },
                                                   ComponentVariables:             new[] {
                                                                                       new OCPPv2_1.ComponentVariable(
                                                                                           new OCPPv2_1.Component(
                                                                                               Name:       commandArray[1],
                                                                                               Instance:   null,
                                                                                               EVSE:       null
                                                                                           ),
                                                                                           commandArray.Length == 3
                                                                                               ? new OCPPv2_1.Variable(
                                                                                                     Name:       commandArray[2],
                                                                                                     Instance:   null
                                                                                                 )
                                                                                               : null
                                                                                       )
                                                                                   }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SetMonitoringLevel

                        //   SetMonitoringLevel debug
                        //   SetMonitoringLevel informational
                        //   SetMonitoringLevel notice
                        //   SetMonitoringLevel warning
                        //   SetMonitoringLevel alert
                        //   SetMonitoringLevel critical
                        //   SetMonitoringLevel systemfailure
                        //   SetMonitoringLevel hardwarefailure
                        //   SetMonitoringLevel danger
                        if (command == "SetMonitoringLevel".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.SetMonitoringLevel(
                                               new OCPPv2_1.CSMS.SetMonitoringLevelRequest(
                                                   ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   Severity:      commandArray[1].ToLower() switch {
                                                                      "danger"           => OCPPv2_1.Severities.Danger,
                                                                      "hardwarefailure"  => OCPPv2_1.Severities.HardwareFailure,
                                                                      "systemfailure"    => OCPPv2_1.Severities.SystemFailure,
                                                                      "critical"         => OCPPv2_1.Severities.Critical,
                                                                      "alert"            => OCPPv2_1.Severities.Alert,
                                                                      "warning"          => OCPPv2_1.Severities.Warning,
                                                                      "notice"           => OCPPv2_1.Severities.Notice,
                                                                      "informational"    => OCPPv2_1.Severities.Informational,
                                                                      "debug"            => OCPPv2_1.Severities.Debug,
                                                                      _                  => OCPPv2_1.Severities.Error
                                                                  }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region ClearVariableMonitoring

                        //   ClearVariableMonitoring 1
                        if (command == "ClearVariableMonitoring".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.ClearVariableMonitoring(
                                               new OCPPv2_1.CSMS.ClearVariableMonitoringRequest(
                                                   ChargeBoxId:             OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   VariableMonitoringIds:   new[] {
                                                                                OCPPv2_1.VariableMonitoring_Id.Parse(commandArray[1])
                                                                            }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        // SetNetworkProfile

                        #region Change Availability

                        //   ChangeAvailability operative
                        //   ChangeAvailability inoperative
                        if (command == "ChangeAvailability".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.ChangeAvailability(
                                               new OCPPv2_1.CSMS.ChangeAvailabilityRequest(
                                                   ChargeBoxId:         OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   OperationalStatus:   commandArray[1].ToLower() switch {
                                                                            "operative"  => OCPPv2_1.OperationalStatus.Operative,
                                                                            _            => OCPPv2_1.OperationalStatus.Inoperative
                                                                        }
                                               )
                                           );


                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        //   ChangeAvailability 1 operative
                        //   ChangeAvailability 1 inoperative
                        if (command == "ChangeAvailability".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.ChangeAvailability(
                                                   ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   ConnectorId:    OCPPv1_6.Connector_Id.Parse(commandArray[1]),
                                                   Availability:   commandArray[2].ToLower() switch {
                                                                       "operative"  => OCPPv1_6.Availabilities.Operative,
                                                                       _            => OCPPv1_6.Availabilities.Inoperative
                                                                   }
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.ChangeAvailability(
                                                   new OCPPv2_1.CSMS.ChangeAvailabilityRequest(
                                                       ChargeBoxId:         OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       OperationalStatus:   commandArray[2].ToLower() switch {
                                                                                "operative"  => OCPPv2_1.OperationalStatus.Operative,
                                                                                _            => OCPPv2_1.OperationalStatus.Inoperative
                                                                            },
                                                       EVSE:                new OCPPv2_1.EVSE(
                                                                                Id:  OCPPv2_1.EVSE_Id.Parse(commandArray[1])
                                                                            )
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }



                        //   ChangeAvailability 1 1 operative
                        //   ChangeAvailability 1 1 inoperative
                        if (command == "ChangeAvailability".ToLower() && commandArray.Length == 4)
                        {

                            var response = await testCSMSv2_1.ChangeAvailability(
                                               new OCPPv2_1.CSMS.ChangeAvailabilityRequest(
                                                   ChargeBoxId:         OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   OperationalStatus:   commandArray[3].ToLower() switch {
                                                                            "operative"  => OCPPv2_1.OperationalStatus.Operative,
                                                                            _            => OCPPv2_1.OperationalStatus.Inoperative
                                                                        },
                                                   EVSE:                new OCPPv2_1.EVSE(
                                                                            Id:            OCPPv2_1.EVSE_Id.     Parse(commandArray[1]),
                                                                            ConnectorId:   OCPPv2_1.Connector_Id.Parse(commandArray[2])
                                                                        )
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Trigger Message

                        //   TriggerMessage BootNotification
                        //   TriggerMessage LogStatusNotification
                        //   TriggerMessage DiagnosticsStatusNotification
                        //   TriggerMessage FirmwareStatusNotification
                        //   TriggerMessage Heartbeat
                        //   TriggerMessage MeterValues
                        //   TriggerMessage SignChargePointCertificate
                        //   TriggerMessage StatusNotification
                        if (command == "TriggerMessage".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.TriggerMessage(
                                                   ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   RequestedMessage:   commandArray[1].ToLower() switch {
                                                                           "bootnotification"               => OCPPv1_6.MessageTriggers.BootNotification,
                                                                           "logstatusnotification"          => OCPPv1_6.MessageTriggers.LogStatusNotification,
                                                                           "diagnosticsstatusnotification"  => OCPPv1_6.MessageTriggers.DiagnosticsStatusNotification,
                                                                           "firmwarestatusnotification"     => OCPPv1_6.MessageTriggers.FirmwareStatusNotification,
                                                                           "metervalues"                    => OCPPv1_6.MessageTriggers.MeterValues,
                                                                           "signchargepointcertificate"     => OCPPv1_6.MessageTriggers.SignChargePointCertificate,
                                                                           "statusnotification"             => OCPPv1_6.MessageTriggers.StatusNotification,
                                                                           _                                => OCPPv1_6.MessageTriggers.Heartbeat
                                                                       }
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.TriggerMessage(
                                                   new OCPPv2_1.CSMS.TriggerMessageRequest(
                                                       ChargeBoxId:        OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       RequestedMessage:   commandArray[1].ToLower() switch {
                                                                               "bootnotification"               => OCPPv2_1.MessageTriggers.BootNotification,
                                                                               "logstatusnotification"          => OCPPv2_1.MessageTriggers.LogStatusNotification,
                                                                               "diagnosticsstatusnotification"  => OCPPv2_1.MessageTriggers.DiagnosticsStatusNotification,
                                                                               "firmwarestatusnotification"     => OCPPv2_1.MessageTriggers.FirmwareStatusNotification,
                                                                               "metervalues"                    => OCPPv2_1.MessageTriggers.MeterValues,
                                                                               "signchargepointcertificate"     => OCPPv2_1.MessageTriggers.SignChargePointCertificate,
                                                                               "statusnotification"             => OCPPv2_1.MessageTriggers.StatusNotification,
                                                                               _                                => OCPPv2_1.MessageTriggers.Heartbeat
                                                                           }
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }



                        //   TriggerMessage 1 BootNotification
                        //   TriggerMessage 1 LogStatusNotification
                        //   TriggerMessage 1 DiagnosticsStatusNotification
                        //   TriggerMessage 1 FirmwareStatusNotification
                        //   TriggerMessage 1 Heartbeat
                        //   TriggerMessage 1 MeterValues
                        //   TriggerMessage 1 SignChargePointCertificate
                        //   TriggerMessage 1 StatusNotification
                        if (command == "TriggerMessage".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.TriggerMessage(
                                                   ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   RequestedMessage:   commandArray[2].ToLower() switch {
                                                                           "bootnotification"               => OCPPv1_6.MessageTriggers.BootNotification,
                                                                           "logstatusnotification"          => OCPPv1_6.MessageTriggers.LogStatusNotification,
                                                                           "diagnosticsstatusnotification"  => OCPPv1_6.MessageTriggers.DiagnosticsStatusNotification,
                                                                           "firmwarestatusnotification"     => OCPPv1_6.MessageTriggers.FirmwareStatusNotification,
                                                                           "metervalues"                    => OCPPv1_6.MessageTriggers.MeterValues,
                                                                           "signchargepointcertificate"     => OCPPv1_6.MessageTriggers.SignChargePointCertificate,
                                                                           "statusnotification"             => OCPPv1_6.MessageTriggers.StatusNotification,
                                                                           _                                => OCPPv1_6.MessageTriggers.Heartbeat
                                                                       },
                                                   ConnectorId:        OCPPv1_6.Connector_Id.Parse(commandArray[1])
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.TriggerMessage(
                                                   new OCPPv2_1.CSMS.TriggerMessageRequest(
                                                       ChargeBoxId:        OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       RequestedMessage:   commandArray[2].ToLower() switch {
                                                                               "bootnotification"               => OCPPv2_1.MessageTriggers.BootNotification,
                                                                               "logstatusnotification"          => OCPPv2_1.MessageTriggers.LogStatusNotification,
                                                                               "diagnosticsstatusnotification"  => OCPPv2_1.MessageTriggers.DiagnosticsStatusNotification,
                                                                               "firmwarestatusnotification"     => OCPPv2_1.MessageTriggers.FirmwareStatusNotification,
                                                                               "metervalues"                    => OCPPv2_1.MessageTriggers.MeterValues,
                                                                               "signchargepointcertificate"     => OCPPv2_1.MessageTriggers.SignChargePointCertificate,
                                                                               "statusnotification"             => OCPPv2_1.MessageTriggers.StatusNotification,
                                                                               _                                => OCPPv2_1.MessageTriggers.Heartbeat
                                                                           },
                                                       EVSEId:             OCPPv2_1.EVSE_Id.Parse(commandArray[1])
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region Update Firmware

                        //   UpdateFirmware http://95.89.178.27:9901/firmware.bin
                        if (command == "UpdateFirmware".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.UpdateFirmware(
                                                   ChargeBoxId:         OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   FirmwareURL:         URL.Parse(commandArray[1]),
                                                   RetrieveTimestamp:   Timestamp.Now + TimeSpan.FromMinutes(1)
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.UpdateFirmware(
                                                   new OCPPv2_1.CSMS.UpdateFirmwareRequest(
                                                       ChargeBoxId:               OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       Firmware:                  new OCPPv2_1.Firmware(
                                                                                      FirmwareURL:          URL.Parse(commandArray[2]),
                                                                                      RetrieveTimestamp:    Timestamp.Now,
                                                                                      InstallTimestamp:     Timestamp.Now + TimeSpan.FromMinutes(1),
                                                                                      SigningCertificate:   null,
                                                                                      Signature:            null
                                                                                  ),
                                                       UpdateFirmwareRequestId:   RandomExtensions.RandomInt32(),
                                                       Retries:                   3,
                                                       RetryInterval:             TimeSpan.FromSeconds(10)
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region ExtendedTriggerMessage (OCPP v1.6)

                        //   ExtendedTriggerMessage BootNotification
                        //   ExtendedTriggerMessage LogStatusNotification
                        //   ExtendedTriggerMessage DiagnosticsStatusNotification
                        //   ExtendedTriggerMessage FirmwareStatusNotification
                        //   ExtendedTriggerMessage Heartbeat
                        //   ExtendedTriggerMessage MeterValues
                        //   ExtendedTriggerMessage SignChargePointCertificate
                        //   ExtendedTriggerMessage StatusNotification
                        if (command == "ExtendedTriggerMessage".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.ExtendedTriggerMessage(
                                               ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                               RequestedMessage:   commandArray[1].ToLower() switch {
                                                                       "bootnotification"               => OCPPv1_6.MessageTriggers.BootNotification,
                                                                       "logstatusnotification"          => OCPPv1_6.MessageTriggers.LogStatusNotification,
                                                                       "diagnosticsstatusnotification"  => OCPPv1_6.MessageTriggers.DiagnosticsStatusNotification,
                                                                       "firmwarestatusnotification"     => OCPPv1_6.MessageTriggers.FirmwareStatusNotification,
                                                                       "metervalues"                    => OCPPv1_6.MessageTriggers.MeterValues,
                                                                       "signchargepointcertificate"     => OCPPv1_6.MessageTriggers.SignChargePointCertificate,
                                                                       "statusnotification"             => OCPPv1_6.MessageTriggers.StatusNotification,
                                                                       _                                => OCPPv1_6.MessageTriggers.Heartbeat
                                                                   }
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }




                        //   ExtendedTriggerMessage 1 BootNotification
                        //   ExtendedTriggerMessage 1 LogStatusNotification
                        //   ExtendedTriggerMessage 1 DiagnosticsStatusNotification
                        //   ExtendedTriggerMessage 1 FirmwareStatusNotification
                        //   ExtendedTriggerMessage 1 Heartbeat
                        //   ExtendedTriggerMessage 1 MeterValues
                        //   ExtendedTriggerMessage 1 SignChargePointCertificate
                        //   ExtendedTriggerMessage 1 StatusNotification
                        if (command == "ExtendedTriggerMessage".ToLower() && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.ExtendedTriggerMessage(
                                               ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                               RequestedMessage:   commandArray[2].ToLower() switch {
                                                                       "bootnotification"               => OCPPv1_6.MessageTriggers.BootNotification,
                                                                       "logstatusnotification"          => OCPPv1_6.MessageTriggers.LogStatusNotification,
                                                                       "diagnosticsstatusnotification"  => OCPPv1_6.MessageTriggers.DiagnosticsStatusNotification,
                                                                       "firmwarestatusnotification"     => OCPPv1_6.MessageTriggers.FirmwareStatusNotification,
                                                                       "metervalues"                    => OCPPv1_6.MessageTriggers.MeterValues,
                                                                       "signchargepointcertificate"     => OCPPv1_6.MessageTriggers.SignChargePointCertificate,
                                                                       "statusnotification"             => OCPPv1_6.MessageTriggers.StatusNotification,
                                                                       _                                => OCPPv1_6.MessageTriggers.Heartbeat
                                                                   },
                                               ConnectorId:        OCPPv1_6.Connector_Id.Parse(commandArray[1])
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Transfer Data

                        //   TransferData graphdefined
                        if (command == "transferdata".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.DataTransfer(
                                                   ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   VendorId:      commandArray[1]
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.TransferData(
                                                   new OCPPv2_1.CSMS.DataTransferRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       VendorId:      OCPPv2_1.Vendor_Id.   Parse(commandArray[1])
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }




                        //   TransferData graphdefined message
                        if (command == "transferdata".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.DataTransfer(
                                                   ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   VendorId:      commandArray[1],
                                                   MessageId:     commandArray[2]
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.TransferData(
                                                   new OCPPv2_1.CSMS.DataTransferRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       VendorId:      OCPPv2_1.Vendor_Id.   Parse(commandArray[1]),
                                                       MessageId:     commandArray[2]
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }




                        //   TransferData graphdefined message data
                        if (command == "transferdata".ToLower() && commandArray.Length == 4)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.DataTransfer(
                                                   ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   VendorId:      commandArray[1],
                                                   MessageId:     commandArray[2],
                                                   Data:          commandArray[3]
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.TransferData(
                                                   new OCPPv2_1.CSMS.DataTransferRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       VendorId:      OCPPv2_1.Vendor_Id.   Parse(commandArray[1]),
                                                       MessageId:     commandArray[2],
                                                       Data:          commandArray[3]
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion


                        #region SendSignedCertificate

                        //   SendSignedCertificate $Filename
                        if (command == "SendSignedCertificate".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.CertificateSigned(
                                                   ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   CertificateChain:   OCPPv1_6.CertificateChain.Parse(
                                                                           File.ReadAllText(commandArray[1])
                                                                       )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {
                                // not allowed!
                            }

                        }



                        //   SendSignedCertificate $Filename v2g|csc
                        if (command == "SendSignedCertificate".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {
                                // not allowed!
                            }
                            else
                            {

                                var response = await testCSMSv2_1.SendSignedCertificate(
                                                   new OCPPv2_1.CSMS.CertificateSignedRequest(
                                                       ChargeBoxId:        OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       CertificateChain:   OCPPv2_1.CertificateChain.Parse(
                                                                               File.ReadAllText(commandArray[1])
                                                                           ),
                                                       CertificateType:    commandArray[2].ToLower() switch {
                                                                               "v2g"  => OCPPv2_1.CertificateSigningUse.V2GCertificate,
                                                                               _      => OCPPv2_1.CertificateSigningUse.ChargingStationCertificate
                                                                           }
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region InstallCertificate

                        if (command == "InstallCertificate".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                //   InstallCertificate $FileName csrc|mrc
                                var response = await testCSMSv1_6.InstallCertificate(
                                                   ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   CertificateType:   commandArray[2].ToLower() switch {
                                                                          "csrc"  => OCPPv1_6.CertificateUse.CentralSystemRootCertificate,
                                                                          _       => OCPPv1_6.CertificateUse.ManufacturerRootCertificate
                                                                      },
                                                   Certificate:       OCPPv1_6.Certificate.Parse(
                                                                          File.ReadAllText(commandArray[1])
                                                                      )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                //   InstallCertificate $FileName v2grc|morc|csrc|v2gcc
                                var response = await testCSMSv2_1.InstallCertificate(
                                                   new OCPPv2_1.CSMS.InstallCertificateRequest(
                                                       ChargeBoxId:       OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       CertificateType:   commandArray[2].ToLower() switch {
                                                                              "v2grc"  => OCPPv2_1.CertificateUse.V2GRootCertificate,
                                                                              "morc"   => OCPPv2_1.CertificateUse.MORootCertificate,
                                                                              "csrc"   => OCPPv2_1.CertificateUse.CSMSRootCertificate,
                                                                              _        => OCPPv2_1.CertificateUse.V2GCertificateChain
                                                                          },
                                                       Certificate:       OCPPv2_1.Certificate.Parse(
                                                                              File.ReadAllText(commandArray[1])
                                                                          )
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region GetInstalledCertificateIds

                        if (command == "GetInstalledCertificateIds".ToLower() && commandArray.Length == 2)
                        {

                            //   GetInstalledCertificateIds csrc
                            //   GetInstalledCertificateIds mrc
                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.GetInstalledCertificateIds(
                                                   ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   CertificateType:   commandArray[1].ToLower() switch {
                                                                          "csrc"  => OCPPv1_6.CertificateUse.CentralSystemRootCertificate,
                                                                          _       => OCPPv1_6.CertificateUse.ManufacturerRootCertificate
                                                                      }
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                //   GetInstalledCertificateIds v2grc
                                //   GetInstalledCertificateIds morc
                                //   GetInstalledCertificateIds csrc
                                //   GetInstalledCertificateIds v2gcc
                                var response = await testCSMSv2_1.GetInstalledCertificateIds(
                                                   new OCPPv2_1.CSMS.GetInstalledCertificateIdsRequest(
                                                       ChargeBoxId:        OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       CertificateTypes:   new[] {
                                                                               commandArray[1].ToLower() switch {
                                                                                   "v2grc"  => OCPPv2_1.CertificateUse.V2GRootCertificate,
                                                                                   "morc"   => OCPPv2_1.CertificateUse.MORootCertificate,
                                                                                   "csrc"   => OCPPv2_1.CertificateUse.CSMSRootCertificate,
                                                                                   _        => OCPPv2_1.CertificateUse.V2GCertificateChain
                                                                               }
                                                                           }
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region DeleteCertificate

                        //   DeleteCertificate $HashAlgorithm $IssuerNameHash $IssuerPublicKeyHash $SerialNumber
                        if (command == "DeleteCertificate".ToLower() && commandArray.Length == 5)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.DeleteCertificate(
                                                   ChargeBoxId:           OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   CertificateHashData:   new OCPPv1_6.CertificateHashData(
                                                                              commandArray[1].ToLower() switch {
                                                                                  "sha512"  => OCPPv1_6.HashAlgorithms.SHA512,
                                                                                  "sha384"  => OCPPv1_6.HashAlgorithms.SHA384,
                                                                                  _         => OCPPv1_6.HashAlgorithms.SHA256
                                                                              },
                                                                              commandArray[2],
                                                                              commandArray[3],
                                                                              commandArray[4]
                                                                          )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.DeleteCertificate(
                                                   new OCPPv2_1.CSMS.DeleteCertificateRequest(
                                                       ChargeBoxId:           OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       CertificateHashData:   new OCPPv2_1.CertificateHashData(
                                                                                  commandArray[1].ToLower() switch {
                                                                                      "sha512"  => OCPPv2_1.HashAlgorithms.SHA512,
                                                                                      "sha384"  => OCPPv2_1.HashAlgorithms.SHA384,
                                                                                      _         => OCPPv2_1.HashAlgorithms.SHA256
                                                                                  },
                                                                                  commandArray[2],
                                                                                  commandArray[3],
                                                                                  commandArray[4]
                                                                              )
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        // NotifyCRLAvailability


                        #region GetLocalListVersion

                        //   getlocallistversion GD002
                        if (command == "getlocallistversion"    && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.GetLocalListVersion(OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SendLocalList

                        //   sendlocallist GD002
                        if (command == "sendlocallist"          && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.SendLocalList(OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                                 2, // 0 is not allowed!
                                                                                 OCPPv1_6.UpdateTypes.Full,
                                                                                 new OCPPv1_6.AuthorizationData[] {
                                                                                     new OCPPv1_6.AuthorizationData(OCPPv1_6.IdToken.Parse("046938f2fc6880"), new OCPPv1_6.IdTagInfo(OCPPv1_6.AuthorizationStatus.Blocked)),
                                                                                     new OCPPv1_6.AuthorizationData(OCPPv1_6.IdToken.Parse("aabbcc11"),       new OCPPv1_6.IdTagInfo(OCPPv1_6.AuthorizationStatus.Accepted)),
                                                                                     new OCPPv1_6.AuthorizationData(OCPPv1_6.IdToken.Parse("aabbcc22"),       new OCPPv1_6.IdTagInfo(OCPPv1_6.AuthorizationStatus.Accepted)),
                                                                                     new OCPPv1_6.AuthorizationData(OCPPv1_6.IdToken.Parse("aabbcc33"),       new OCPPv1_6.IdTagInfo(OCPPv1_6.AuthorizationStatus.Accepted)),
                                                                                     new OCPPv1_6.AuthorizationData(OCPPv1_6.IdToken.Parse("aabbcc44"),       new OCPPv1_6.IdTagInfo(OCPPv1_6.AuthorizationStatus.Blocked))
                                                                                 });

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region ClearCache

                        //   clearcache GD002
                        if (command == "clearcache"             && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.ClearCache(OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region ReserveNow

                        //   ReserveNow 1 $ReservationId aabbccdd
                        if (command == "ReserveNow" && commandArray.Length == 4)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.ReserveNow(
                                                   ChargeBoxId:     OCPPv1_6.ChargeBox_Id.  Parse(chargeBoxId),
                                                   ConnectorId:     OCPPv1_6.Connector_Id.  Parse(commandArray[1]),
                                                   ReservationId:   OCPPv1_6.Reservation_Id.Parse(commandArray[2]),
                                                   ExpiryDate:      Timestamp.Now + TimeSpan.FromMinutes(15),
                                                   IdTag:           OCPPv1_6.IdToken.       Parse(commandArray[3])
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.ReserveNow(
                                                   new OCPPv2_1.CSMS.ReserveNowRequest(
                                                       ChargeBoxId:     OCPPv2_1.ChargeBox_Id.  Parse(chargeBoxId),
                                                       ReservationId:   OCPPv2_1.Reservation_Id.Parse(commandArray[2]),
                                                       ExpiryDate:      Timestamp.Now + TimeSpan.FromMinutes(15),
                                                       IdToken:         new OCPPv2_1.IdToken(
                                                                            Value:             commandArray[3],
                                                                            Type:              OCPPv2_1.IdTokenTypes.eMAID,
                                                                            AdditionalInfos:   null
                                                                        ),
                                                       ConnectorType:   null, //OCPPv2_1.ConnectorTypes.sType2,
                                                       EVSEId:          OCPPv2_1.EVSE_Id.       Parse(commandArray[1]),
                                                       GroupIdToken:    null
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region Cancel Reservation

                        //   CancelReservation $ReservationId
                        if (command == "CancelReservation" && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.CancelReservation(
                                                   ChargeBoxId:     OCPPv1_6.ChargeBox_Id.  Parse(chargeBoxId),
                                                   ReservationId:   OCPPv1_6.Reservation_Id.Parse(commandArray[1])
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.CancelReservation(
                                                   new OCPPv2_1.CSMS.CancelReservationRequest(
                                                       ChargeBoxId:     OCPPv2_1.ChargeBox_Id.  Parse(chargeBoxId),
                                                       ReservationId:   OCPPv2_1.Reservation_Id.Parse(commandArray[1])
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region Remote Start Transaction

                        //   RemoteStart 1 $IdToken
                        if (command == "remotestart".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.RemoteStartTransaction(
                                                   ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   IdTag:             OCPPv1_6.IdToken.     Parse(commandArray[2]),
                                                   ConnectorId:       OCPPv1_6.Connector_Id.Parse(commandArray[1]),
                                                   ChargingProfile:   null
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.StartCharging(
                                                   new OCPPv2_1.CSMS.RequestStartTransactionRequest(
                                                       ChargeBoxId:                        OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       RequestStartTransactionRequestId:   OCPPv2_1.RemoteStart_Id.NewRandom,
                                                       IdToken:                            new OCPPv2_1.IdToken(
                                                                                               Value:             commandArray[2],
                                                                                               Type:              OCPPv2_1.IdTokenTypes.eMAID,
                                                                                               AdditionalInfos:   null
                                                                                           ),
                                                       EVSEId:                             OCPPv2_1.EVSE_Id.Parse(commandArray[1]),
                                                       ChargingProfile:                    null,
                                                       GroupIdToken:                       null
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region Remote Stop Transaction

                        //   RemoteStop $TransactionId
                        if (command == "RemoteStop".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.RemoteStopTransaction(
                                                   ChargeBoxId:     OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   TransactionId:   OCPPv1_6.Transaction_Id.Parse(commandArray[1])
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.StopCharging(
                                                   new OCPPv2_1.CSMS.RequestStopTransactionRequest(
                                                       ChargeBoxId:     OCPPv2_1.ChargeBox_Id.  Parse(chargeBoxId),
                                                       TransactionId:   OCPPv2_1.Transaction_Id.Parse(commandArray[1])
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region GetTransactionStatus

                        //   GetTransactionStatus
                        if (command == "GetTransactionStatus".ToLower() && commandArray.Length == 1)
                        {

                            var response = await testCSMSv2_1.GetTransactionStatus(
                                               new OCPPv2_1.CSMS.GetTransactionStatusRequest(
                                                   ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId)
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        //   GetTransactionStatus $TransactionId
                        if (command == "GetTransactionStatus".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.GetTransactionStatus(
                                               new OCPPv2_1.CSMS.GetTransactionStatusRequest(
                                                   ChargeBoxId:     OCPPv2_1.ChargeBox_Id.  Parse(chargeBoxId),
                                                   TransactionId:   OCPPv2_1.Transaction_Id.Parse(commandArray[1])
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SetChargingProfile

                        //   setprofile1 GD002 1
                        if (command == "setprofile1"            && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.SetChargingProfile(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                                 ConnectorId:      OCPPv1_6.Connector_Id.Parse(commandArray[2]),
                                                                                 ChargingProfile:  new OCPPv1_6.ChargingProfile(
                                                                                                       OCPPv1_6.ChargingProfile_Id.Parse("100"),
                                                                                                       0,
                                                                                                       OCPPv1_6.ChargingProfilePurposes.TxDefaultProfile,
                                                                                                       OCPPv1_6.ChargingProfileKinds.Recurring,
                                                                                                       new OCPPv1_6.ChargingSchedule(
                                                                                                           ChargingRateUnit:         OCPPv1_6.ChargingRateUnits.Amperes,
                                                                                                           ChargingSchedulePeriods:  new OCPPv1_6.ChargingSchedulePeriod[] {
                                                                                                                                         new OCPPv1_6.ChargingSchedulePeriod(
                                                                                                                                             StartPeriod:   TimeSpan.FromHours(0),  // == 00:00 Uhr
                                                                                                                                             Limit:         16,
                                                                                                                                             NumberPhases:  3
                                                                                                                                         ),
                                                                                                                                         new OCPPv1_6.ChargingSchedulePeriod(
                                                                                                                                             StartPeriod:   TimeSpan.FromHours(8),  // == 08:00 Uhr
                                                                                                                                             Limit:         6,
                                                                                                                                             NumberPhases:  3
                                                                                                                                         ),
                                                                                                                                         new OCPPv1_6.ChargingSchedulePeriod(
                                                                                                                                             StartPeriod:   TimeSpan.FromHours(20), // == 20:00 Uhr
                                                                                                                                             Limit:         12,
                                                                                                                                             NumberPhases:  3
                                                                                                                                         )
                                                                                                                                     },
                                                                                                           Duration:                 TimeSpan.FromDays(7),
                                                                                                           StartSchedule:            DateTime.Parse("2023-03-29T00:00:00Z").ToUniversalTime()

                                                                                                       ),
                                                                                                       null, //Transaction_Id.TryParse(5678),
                                                                                                       OCPPv1_6.RecurrencyKinds.Daily,
                                                                                                       DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime(),
                                                                                                       DateTime.Parse("2023-12-01T00:00:00Z").ToUniversalTime()
                                                                                                   ));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   setprofile2 GD002 1
                        if (command == "setprofile2"            && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.SetChargingProfile(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                                 ConnectorId:      OCPPv1_6.Connector_Id.Parse(commandArray[2]),
                                                                                 ChargingProfile:  new OCPPv1_6.ChargingProfile(
                                                                                                       OCPPv1_6.ChargingProfile_Id.Parse("100"),
                                                                                                       2,
                                                                                                       OCPPv1_6.ChargingProfilePurposes.TxProfile,
                                                                                                       OCPPv1_6.ChargingProfileKinds.Recurring,
                                                                                                       new OCPPv1_6.ChargingSchedule(
                                                                                                           ChargingRateUnit:         OCPPv1_6.ChargingRateUnits.Amperes,
                                                                                                           ChargingSchedulePeriods:  new OCPPv1_6.ChargingSchedulePeriod[] {
                                                                                                                                         new OCPPv1_6.ChargingSchedulePeriod(
                                                                                                                                             StartPeriod:   TimeSpan.FromHours(0),  // == 00:00 Uhr
                                                                                                                                             Limit:         11,
                                                                                                                                             NumberPhases:  3
                                                                                                                                         ),
                                                                                                                                         new OCPPv1_6.ChargingSchedulePeriod(
                                                                                                                                             StartPeriod:   TimeSpan.FromHours(6),  // == 06:00 Uhr
                                                                                                                                             Limit:         6,
                                                                                                                                             NumberPhases:  3
                                                                                                                                         ),
                                                                                                                                         new OCPPv1_6.ChargingSchedulePeriod(
                                                                                                                                             StartPeriod:   TimeSpan.FromHours(21), // == 21:00 Uhr
                                                                                                                                             Limit:         11,
                                                                                                                                             NumberPhases:  3
                                                                                                                                         )
                                                                                                                                     },
                                                                                                           Duration:                 TimeSpan.FromDays(7),
                                                                                                           StartSchedule:            DateTime.Parse("2023-03-29T00:00:00Z").ToUniversalTime()

                                                                                                       ),
                                                                                                       null, //Transaction_Id.TryParse(6789),
                                                                                                       OCPPv1_6.RecurrencyKinds.Daily,
                                                                                                       DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime(),
                                                                                                       DateTime.Parse("2023-12-01T00:00:00Z").ToUniversalTime()
                                                                                                   ));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetChargingProfiles

                        //   GetChargingProfiles
                        if (command == "GetChargingProfiles".ToLower() && commandArray.Length == 1)
                        {

                            var response = await testCSMSv2_1.GetChargingProfiles(
                                               new OCPPv2_1.CSMS.GetChargingProfilesRequest(
                                                   ChargeBoxId:                    OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetChargingProfilesRequestId:   RandomExtensions.RandomInt32(),
                                                   ChargingProfile:                new OCPPv2_1.ChargingProfileCriterion(
                                                                                       ChargingProfilePurpose:   OCPPv2_1.ChargingProfilePurposes.TxDefaultProfile,
                                                                                       StackLevel:               null,
                                                                                       ChargingProfileIds:       null,
                                                                                       ChargingLimitSources:     null
                                                                                   ),
                                                   EVSEId:                         null
                                               )
                                           );;

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        //   GetChargingProfiles $ChargingProfileId
                        if (command == "GetChargingProfiles".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.GetChargingProfiles(
                                               new OCPPv2_1.CSMS.GetChargingProfilesRequest(
                                                   ChargeBoxId:                    OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetChargingProfilesRequestId:   RandomExtensions.RandomInt32(),
                                                   ChargingProfile:                new OCPPv2_1.ChargingProfileCriterion(
                                                                                       ChargingProfilePurpose:   null,
                                                                                       StackLevel:               null,
                                                                                       ChargingProfileIds:       new[] {
                                                                                                                     OCPPv2_1.ChargingProfile_Id.Parse(commandArray[1])
                                                                                                                 },
                                                                                       ChargingLimitSources:     null
                                                                                   ),
                                                   EVSEId:                         null
                                               )
                                           );;

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region ClearChargingProfile

                        //   ClearChargingProfile
                        if (command == "ClearChargingProfile".ToLower() && commandArray.Length == 1)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.ClearChargingProfile(
                                                   ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId)
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.ClearChargingProfile(
                                                   new OCPPv2_1.CSMS.ClearChargingProfileRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId)
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }



                        //   ClearChargingProfile $ChargingProfileId
                        if (command == "ClearChargingProfile".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.ClearChargingProfile(
                                                   ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   ChargingProfileId:  OCPPv1_6.ChargingProfile_Id.Parse(commandArray[1])
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.ClearChargingProfile(
                                                   new OCPPv2_1.CSMS.ClearChargingProfileRequest(
                                                       ChargeBoxId:         OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       ChargingProfileId:   OCPPv2_1.ChargingProfile_Id.Parse(commandArray[1])
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }



                        //   ClearChargingProfile $ConnectorId/EVSEId $ChargingProfileId
                        if (command == "ClearChargingProfile".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                //   ClearChargingProfile $ConnectorId $ChargingProfileId
                                var response = await testCSMSv1_6.ClearChargingProfile(
                                                   ChargeBoxId:              OCPPv1_6.ChargeBox_Id.      Parse(chargeBoxId),
                                                   ChargingProfileId:        OCPPv1_6.ChargingProfile_Id.Parse(commandArray[2]),
                                                   ConnectorId:              OCPPv1_6.Connector_Id.      Parse(commandArray[1]),
                                                   ChargingProfilePurpose:   null,
                                                   StackLevel:               null
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                //   ClearChargingProfile $EVSEId $ChargingProfileId
                                var response = await testCSMSv2_1.ClearChargingProfile(
                                                   new OCPPv2_1.CSMS.ClearChargingProfileRequest(
                                                       ChargeBoxId:               OCPPv2_1.ChargeBox_Id.      Parse(chargeBoxId),
                                                       ChargingProfileId:         OCPPv2_1.ChargingProfile_Id.Parse(commandArray[2]),
                                                       ChargingProfileCriteria:   new OCPPv2_1.ClearChargingProfile(
                                                                                      EVSEId:                   OCPPv2_1.EVSE_Id.Parse(commandArray[1]),
                                                                                      ChargingProfilePurpose:   null,
                                                                                      StackLevel:               null
                                                                                  )
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region GetCompositeSchedule

                        //   GetCompositeSchedule 1 3600
                        if (command == "GetCompositeSchedule".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.GetCompositeSchedule(
                                                   ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   ConnectorId:   OCPPv1_6.Connector_Id.Parse(commandArray[1]),
                                                   Duration:      TimeSpan.FromSeconds(UInt32.Parse(commandArray[2]))
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_1.GetCompositeSchedule(
                                                   new OCPPv2_1.CSMS.GetCompositeScheduleRequest(
                                                       ChargeBoxId:        OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       Duration:           TimeSpan.FromSeconds(UInt32.Parse(commandArray[2])),
                                                       EVSEId:             OCPPv2_1.EVSE_Id.Parse(commandArray[1]),
                                                       ChargingRateUnit:   null
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        // UpdateDynamicSchedule

                        // NotifyAllowedenergyTransfer

                        // UsePriorityCharging

                        #region Unlock Connector

                        //   UnlockConnector 1
                        if (command == "UnlockConnector".ToLower() && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.UnlockConnector(
                                                   ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                   ConnectorId:   OCPPv1_6.Connector_Id.Parse(commandArray[1])
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {
                                // not allowed!
                            }

                        }



                        //   UnlockConnector 1 1
                        if (command == "UnlockConnector".ToLower() && commandArray.Length == 3)
                        {

                            if (version == 1)
                            {
                                // not allowed!
                            }
                            else
                            {

                                var response = await testCSMSv2_1.UnlockConnector(
                                                   new OCPPv2_1.CSMS.UnlockConnectorRequest(
                                                       ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                       EVSEId:        OCPPv2_1.EVSE_Id.     Parse(commandArray[1]),
                                                       ConnectorId:   OCPPv2_1.Connector_Id.Parse(commandArray[2])
                                                   )
                                               );

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion


                        // SendAFDRSignal


                        #region SetDisplayMessage

                        //   SetDisplayMessage test123
                        if (command == "SetDisplayMessage".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.SetDisplayMessage(
                                               new OCPPv2_1.CSMS.SetDisplayMessageRequest(
                                                   ChargeBoxId:   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   Message:       new OCPPv2_1.MessageInfo(
                                                                      Id:               OCPPv2_1.DisplayMessage_Id.NewRandom,
                                                                      Priority:         OCPPv2_1.MessagePriorities.NormalCycle,
                                                                      Message:          new OCPPv2_1.MessageContent(
                                                                                            commandArray[1],
                                                                                            OCPPv2_1.MessageFormats.UTF8,
                                                                                            OCPPv2_1.Language_Id.DE
                                                                                        ),
                                                                      State:            OCPPv2_1.MessageStates.Idle,
                                                                      StartTimestamp:   Timestamp.Now,
                                                                      EndTimestamp:     Timestamp.Now + TimeSpan.FromMinutes(1),
                                                                      TransactionId:    null,
                                                                      Display:          null
                                                                  )
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetDisplayMessages

                        //   GetDisplayMessages
                        if (command == "GetDisplayMessages".ToLower() && commandArray.Length == 1)
                        {

                            var response = await testCSMSv2_1.GetDisplayMessages(
                                               new OCPPv2_1.CSMS.GetDisplayMessagesRequest(
                                                   ChargeBoxId:                   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetDisplayMessagesRequestId:   RandomExtensions.RandomInt32(),
                                                   Ids:                           null,
                                                   Priority:                      null,
                                                   State:                         null
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        //   GetDisplayMessages 1
                        if (command == "GetDisplayMessages".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.GetDisplayMessages(
                                               new OCPPv2_1.CSMS.GetDisplayMessagesRequest(
                                                   ChargeBoxId:                   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetDisplayMessagesRequestId:   RandomExtensions.RandomInt32(),
                                                   Ids:                           new[] {
                                                                                      OCPPv2_1.DisplayMessage_Id.Parse(commandArray[1])
                                                                                  },
                                                   Priority:                      null,
                                                   State:                         null
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        //   GetDisplayMessagesByState 1
                        if (command == "GetDisplayMessagesByState".ToLower() && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_1.GetDisplayMessages(
                                               new OCPPv2_1.CSMS.GetDisplayMessagesRequest(
                                                   ChargeBoxId:                   OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   GetDisplayMessagesRequestId:   RandomExtensions.RandomInt32(),
                                                   Ids:                           null,
                                                   Priority:                      null,
                                                   State:                         commandArray[1].ToLower() switch {
                                                                                      "Charging"     => OCPPv2_1.MessageStates.Charging,
                                                                                      "Faulted"      => OCPPv2_1.MessageStates.Faulted,
                                                                                      "Idle"         => OCPPv2_1.MessageStates.Idle,
                                                                                      "Unavailable"  => OCPPv2_1.MessageStates.Unavailable,
                                                                                      _              => OCPPv2_1.MessageStates.Unknown
                                                                                  }
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }
                        #endregion

                        #region SendCostUpdated

                        //   SendCostUpdate 123.45 ABCDEFG
                        if (command == "SendCostUpdate".ToLower() && commandArray.Length == 3)
                        {

                            var response = await testCSMSv2_1.SendCostUpdated(
                                               new OCPPv2_1.CSMS.CostUpdatedRequest(
                                                   ChargeBoxId:     OCPPv2_1.ChargeBox_Id.  Parse(chargeBoxId),
                                                   TotalCost:       Decimal.                Parse(commandArray[1]),
                                                   TransactionId:   OCPPv2_1.Transaction_Id.Parse(commandArray[2])
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region RequestCustomerInformation

                        //   RequestCustomerInformation
                        if (command == "RequestCustomerInformation".ToLower() && commandArray.Length == 1)
                        {

                            var response = await testCSMSv2_1.RequestCustomerInformation(
                                               new OCPPv2_1.CSMS.CustomerInformationRequest(
                                                   ChargeBoxId:                    OCPPv2_1.ChargeBox_Id.Parse(chargeBoxId),
                                                   CustomerInformationRequestId:   RandomExtensions.RandomInt32(),
                                                   Report:                         true,
                                                   Clear:                          false,
                                                   CustomerIdentifier:             null,
                                                   IdToken:                        null,
                                                   CustomerCertificate:            null
                                               )
                                           );

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        // OCPP v1.6 legacies...

                        #region Get Configuration

                        //   getconf GD002
                        if (command == "getconf"                && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.GetConfiguration(ChargeBoxId: OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getconf GD002 key
                        //   getconf GD002 key1 key2
                        if (command == "getconf"                && commandArray.Length > 2)
                        {

                            var response = await testCSMSv1_6.GetConfiguration(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                               Keys:         commandArray.Skip(2));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Change Configuration

                        //   setconf GD002 key value
                        if (command == "setconf"                && commandArray.Length == 4)
                        {

                            var response = await testCSMSv1_6.ChangeConfiguration(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                                  Key:          commandArray[2],
                                                                                  Value:        commandArray[3]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Get Diagnostics

                        //   getdiag GD002 http://23.88.66.160:9901/diagnostics/
                        if (command == "getdiag"                && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.GetDiagnostics(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                             Location:       commandArray[2],
                                                                             StartTime:      null,
                                                                             StopTime:       null,
                                                                             Retries:        null,
                                                                             RetryInterval:  null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getdiag GD002 http://23.88.66.160:9901/diagnostics/ 2022-11-08T10:00:00Z 2022-11-12T18:00:00Z 3 30
                        if (command == "getdiag"                && commandArray.Length == 7)
                        {

                            var response = await testCSMSv1_6.GetDiagnostics(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(chargeBoxId),
                                                                             Location:       commandArray[2],
                                                                             StartTime:      DateTime.Parse(commandArray[3]).ToUniversalTime(),
                                                                             StopTime:       DateTime.Parse(commandArray[4]).ToUniversalTime(),
                                                                             Retries:        Byte.Parse(commandArray[5]),
                                                                             RetryInterval:  TimeSpan.FromSeconds(Byte.Parse(commandArray[6])));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                    }

                }

            } while (!quit);

            foreach (var DebugListener in Trace.Listeners)
                (DebugListener as TextWriterTraceListener)?.Flush();

            #endregion

        }

    }

}
