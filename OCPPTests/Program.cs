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

            #region Setup CSMS v2.0.1

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

            testCSMSv2_1.AddHTTPBasicAuth(OCPPv2_1.ChargeBox_Id.Parse("GD001"), "test123");




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
            //var response04a  = await chargingStation1.SendStatusNotification(Connector_Id.Parse(1), ChargePointStatus.Available, ChargePointErrorCodes.NoError, "info 1", DateTime.UtcNow, "GD", "VEC01");
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

            var       version       = 1;
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


                        if (command == "switch" && commandArray.Length == 2)
                        {

                            if (commandArray[1] == "1" || commandArray[1] == "v1.6")
                                version = 1;

                            if (commandArray[1] == "2" || commandArray[1] == "v2.0")
                                version = 2;

                        }


                        // AddHTTPBasicAuth
                        //   AddHTTPBasicAuth GD002 abcd1234
                        if (command == "AddHTTPBasicAuth" && commandArray.Length == 3)
                        {
                            testCSMSv1_6.AddHTTPBasicAuth(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]), commandArray[2]);
                            testCSMSv2_0_1.AddHTTPBasicAuth(OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[1]), commandArray[2]);
                        }


                        #region Reset

                        //   hardreset GD002
                        if (command == "hardreset"              && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.Reset(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                        ResetType:    OCPPv1_6.ResetTypes.Hard);

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_0_1.Reset(ChargeBoxId:  OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[1]),
                                                                        ResetType:    OCPPv2_0_1.ResetTypes.Immediate);

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        //   softreset GD002
                        if (command == "softreset"              && commandArray.Length == 2)
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.Reset(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                        ResetType:    OCPPv1_6.ResetTypes.Soft);

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_0_1.Reset(ChargeBoxId:  OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[1]),
                                                                        ResetType:    OCPPv2_0_1.ResetTypes.OnIdle);

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        #endregion

                        #region Change Availability

                        //   set inoperative GD002 1
                        if (command == "set"                    && commandArray.Length == 4 && commandArray[1] == "inoperative")
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.ChangeAvailability(ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(commandArray[2]),
                                                                                     ConnectorId:   OCPPv1_6.Connector_Id.Parse(commandArray[3]),
                                                                                     Availability:  OCPPv1_6.Availabilities.Inoperative);

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_0_1.ChangeAvailability(ChargeBoxId:        OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[2]),
                                                                                     OperationalStatus:  OCPPv2_0_1.OperationalStatus.Inoperative,
                                                                                     EVSE:               new OCPPv2_0_1.EVSE(
                                                                                                             Id:  OCPPv2_0_1.EVSE_Id.Parse(commandArray[3])
                                                                                                         ));

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        if (command == "set"                    && commandArray.Length == 5 && commandArray[1] == "inoperative")
                        {
                            if (version == 2)
                            {

                                var response = await testCSMSv2_0_1.ChangeAvailability(ChargeBoxId:        OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[2]),
                                                                                     OperationalStatus:  OCPPv2_0_1.OperationalStatus.Inoperative,
                                                                                     EVSE:               new OCPPv2_0_1.EVSE(
                                                                                                             Id:           OCPPv2_0_1.EVSE_Id.     Parse(commandArray[3]),
                                                                                                             ConnectorId:  OCPPv2_0_1.Connector_Id.Parse(commandArray[4])
                                                                                                         ));

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                        }

                        //   set operative GD002 1
                        if (command == "set"                    && commandArray.Length == 4 && commandArray[1] == "operative")
                        {

                            if (version == 1)
                            {

                                var response = await testCSMSv1_6.ChangeAvailability(ChargeBoxId:   OCPPv1_6.ChargeBox_Id.Parse(commandArray[2]),
                                                                                     ConnectorId:   OCPPv1_6.Connector_Id.Parse(commandArray[3]),
                                                                                     Availability:  OCPPv1_6.Availabilities.Operative);

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                            else
                            {

                                var response = await testCSMSv2_0_1.ChangeAvailability(ChargeBoxId:        OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[2]),
                                                                                     OperationalStatus:  OCPPv2_0_1.OperationalStatus.Operative,
                                                                                     EVSE:               new OCPPv2_0_1.EVSE(
                                                                                                             Id:  OCPPv2_0_1.EVSE_Id.Parse(commandArray[3])
                                                                                                         ));

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }

                        }

                        if (command == "set"                    && commandArray.Length == 5 && commandArray[1] == "operative")
                        {
                            if (version == 2)
                            {

                                var response = await testCSMSv2_0_1.ChangeAvailability(ChargeBoxId:        OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[2]),
                                                                                     OperationalStatus:  OCPPv2_0_1.OperationalStatus.Operative,
                                                                                     EVSE:               new OCPPv2_0_1.EVSE(
                                                                                                             Id:           OCPPv2_0_1.EVSE_Id.     Parse(commandArray[3]),
                                                                                                             ConnectorId:  OCPPv2_0_1.Connector_Id.Parse(commandArray[4])
                                                                                                         ));

                                Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                Console.WriteLine(response.ToJSON());

                            }
                        }

                        #endregion

                        #region Get Configuration

                        //   getconf GD002
                        if (command == "getconf"                && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.GetConfiguration(ChargeBoxId: OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getconf GD002 key
                        //   getconf GD002 key1 key2
                        if (command == "getconf"                && commandArray.Length > 2)
                        {

                            var response = await testCSMSv1_6.GetConfiguration(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                               Keys:         commandArray.Skip(2));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Change Configuration

                        //   setconf GD002 key value
                        if (command == "setconf"                && commandArray.Length == 4)
                        {

                            var response = await testCSMSv1_6.ChangeConfiguration(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                  Key:          commandArray[2],
                                                                                  Value:        commandArray[3]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region OCPP v2.0: GetBaseReport

                        if (command == "getbasereport" && commandArray.Length == 2)
                        {

                            var response = await testCSMSv2_0_1.GetBaseReport(ChargeBoxId:              OCPPv2_0_1.ChargeBox_Id.Parse(commandArray[1]),
                                                                            GetBaseReportRequestId:   1,
                                                                            ReportBase:               OCPPv2_0_1.ReportBases.FullInventory);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region Transfer Data

                        //   transferdata GD002 graphdefined
                        if (command == "transferdata"           && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.DataTransfer(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                           VendorId:     commandArray[2]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   transferdata GD002 graphdefined message
                        if (command == "transferdata"           && commandArray.Length == 4)
                        {

                            var response = await testCSMSv1_6.DataTransfer(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                           VendorId:     commandArray[2],
                                                                           MessageId:    commandArray[3]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   transferdata GD002 graphdefined message data
                        if (command == "transferdata"           && commandArray.Length == 5)
                        {

                            var response = await testCSMSv1_6.DataTransfer(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                           VendorId:     commandArray[2],
                                                                           MessageId:    commandArray[3],
                                                                           Data:         commandArray[4]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Get Diagnostics

                        //   getdiag GD002 http://23.88.66.160:9901/diagnostics/
                        if (command == "getdiag"                && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.GetDiagnostics(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
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

                            var response = await testCSMSv1_6.GetDiagnostics(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             Location:       commandArray[2],
                                                                             StartTime:      DateTime.Parse(commandArray[3]).ToUniversalTime(),
                                                                             StopTime:       DateTime.Parse(commandArray[4]).ToUniversalTime(),
                                                                             Retries:        Byte.Parse(commandArray[5]),
                                                                             RetryInterval:  TimeSpan.FromSeconds(Byte.Parse(commandArray[6])));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Trigger Message

                        //   trigger GD002 BootNotification
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "BootNotification".ToLower())
                        {

                            var response = await testCSMSv1_6.TriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             RequestedMessage:  OCPPv1_6.MessageTriggers.BootNotification);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 DiagnosticsStatusNotification
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "DiagnosticsStatusNotification".ToLower())
                        {

                            var response = await testCSMSv1_6.TriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             RequestedMessage:  OCPPv1_6.MessageTriggers.DiagnosticsStatusNotification);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 FirmwareStatusNotification
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "FirmwareStatusNotification".ToLower())
                        {

                            var response = await testCSMSv1_6.TriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             RequestedMessage:  OCPPv1_6.MessageTriggers.FirmwareStatusNotification);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 Heartbeat
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "Heartbeat".ToLower())
                        {

                            var response = await testCSMSv1_6.TriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             RequestedMessage:  OCPPv1_6.MessageTriggers.Heartbeat);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 MeterValues 1
                        if (command == "trigger"                && commandArray.Length == 4 && commandArray[2].ToLower() == "MeterValues".ToLower())
                        {

                            var response = await testCSMSv1_6.TriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             RequestedMessage:  OCPPv1_6.MessageTriggers.MeterValues,
                                                                             ConnectorId:       OCPPv1_6.Connector_Id.Parse(commandArray[3]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 StatusNotification 1
                        if (command == "trigger"                && commandArray.Length == 4 && commandArray[2].ToLower() == "StatusNotification".ToLower())
                        {

                            var response = await testCSMSv1_6.TriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             RequestedMessage:  OCPPv1_6.MessageTriggers.StatusNotification,
                                                                             ConnectorId:       OCPPv1_6.Connector_Id.Parse(commandArray[3]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Update Firmware
                        //   updatefw GD002 http://95.89.178.27:9901/firmware.bin
                        if (command == "updatefw"               && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.UpdateFirmware(ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                             FirmwareURL:        URL.Parse(commandArray[2]),
                                                                             RetrieveTimestamp:  DateTime.UtcNow + TimeSpan.FromMinutes(1));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region ExtendedTriggerMessage

                        //   extendedtrigger GD002 Heartbeat
                        if (command == "extendedtrigger"        && commandArray.Length == 3 && commandArray[2].ToLower() == "Heartbeat".ToLower())
                        {

                            var response = await testCSMSv1_6.ExtendedTriggerMessage(ChargeBoxId:       OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                     RequestedMessage:  OCPPv1_6.MessageTriggers.Heartbeat);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region Reserve Now

                        //   reserve GD002 1 1234 aabbccdd
                        if (command == "reserve"                && commandArray.Length == 5)
                        {

                            var response = await testCSMSv1_6.ReserveNow(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.  Parse(commandArray[1]),
                                                                         ConnectorId:    OCPPv1_6.Connector_Id.  Parse(commandArray[2]),
                                                                         ReservationId:  OCPPv1_6.Reservation_Id.Parse(commandArray[3]),
                                                                         ExpiryDate:     DateTime.UtcNow + TimeSpan.FromMinutes(15),
                                                                         IdTag:          OCPPv1_6.IdToken.       Parse(commandArray[4]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Cancel Reservation

                        //   cancelreservation GD002 1234
                        if (command == "cancelreservation"      && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.CancelReservation(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.  Parse(commandArray[1]),
                                                                                ReservationId:  OCPPv1_6.Reservation_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Remote Start Transaction

                        //   remotestart GD002 aabbccdd 1
                        if (command == "remotestart"            && commandArray.Length == 4)
                        {

                            var response = await testCSMSv1_6.RemoteStartTransaction(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                     IdTag:        OCPPv1_6.IdToken.     Parse(commandArray[2]),
                                                                                     ConnectorId:  OCPPv1_6.Connector_Id.Parse(commandArray[3]));;

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Remote Stop Transaction

                        //   remotestop GD002 58378535
                        if (command == "remotestop"             && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.RemoteStopTransaction(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.  Parse(commandArray[1]),
                                                                                    TransactionId:  OCPPv1_6.Transaction_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SetChargingProfile

                        //   setprofile1 GD002 1
                        if (command == "setprofile1"            && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.SetChargingProfile(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
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

                            var response = await testCSMSv1_6.SetChargingProfile(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
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

                        #region ClearChargingProfile

                        //   clearprofile GD002 1 100
                        if (command == "clearprofile"           && commandArray.Length >= 2)
                        {

                            var response = await testCSMSv1_6.ClearChargingProfile(ChargeBoxId:        OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                   ChargingProfileId:  commandArray.Length >= 4 ? OCPPv1_6.ChargingProfile_Id.Parse(commandArray[3]) : null,
                                                                                   ConnectorId:        commandArray.Length >= 3 ? OCPPv1_6.Connector_Id.      Parse(commandArray[2]) : null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetCompositeSchedule

                        //   getschedule GD002 1 3600
                        if (command == "getschedule"            && commandArray.Length == 4)
                        {

                            var response = await testCSMSv1_6.GetCompositeSchedule(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.               Parse(commandArray[1]),
                                                                                   ConnectorId:  OCPPv1_6.Connector_Id.               Parse(commandArray[2]),
                                                                                   Duration:     TimeSpan.FromSeconds(UInt32.Parse(commandArray[3])));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region Unlock Connector

                        //   unlock GD002 1
                        if (command == "unlock"                 && commandArray.Length == 3)
                        {

                            var response = await testCSMSv1_6.UnlockConnector(ChargeBoxId:  OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                              ConnectorId:  OCPPv1_6.Connector_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region GetLocalListVersion

                        //   getlocallistversion GD002
                        if (command == "getlocallistversion"    && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.GetLocalListVersion(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region SendLocalList

                        //   sendlocallist GD002
                        if (command == "sendlocallist"          && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.SendLocalList(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
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

                            var response = await testCSMSv1_6.ClearCache(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region CertificateSigned

                        //   certificatesigned GD002
                        if (command == "certificatesigned"      && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.CertificateSigned(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                     OCPPv1_6.CertificateChain.Parse(
                                                                                     String.Concat(
                                                                                         "-----BEGIN CERTIFICATE-----\n",
                                                                                         "MIIFNjCCBB6gAwIBAgISBOChwuPxlU25hKJ2AT4zX+4kMA0GCSqGSIb3DQEBCwUA\n",
                                                                                         "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n",
                                                                                         "EwJSMzAeFw0yMjExMDEwNDA1NThaFw0yMzAxMzAwNDA1NTdaMCMxITAfBgNVBAMT\n",
                                                                                         "GGFwaTEub2NwcC5jaGFyZ2luZy5jbG91ZDCCASIwDQYJKoZIhvcNAQEBBQADggEP\n",
                                                                                         "ADCCAQoCggEBANXXEPaMYd8g3BmOuNLbJC9j5KHEOQebZ71dQcPGrD5pm8TICEmr\n",
                                                                                         "PnAVh/TjF61dco/Bw0HjDz+mI62RHe3tBXggN7p7THKTBLcEMXNMYaEIgp+N1GDV\n",
                                                                                         "4N1ooT9TcnAPID38mjNN/zdPZ2L9IOcE3S9e0AB1a7oJDppvAKIixej+gymuugvy\n",
                                                                                         "DqwDfugfyFXGpuEXm+xl//D5RjN8Mgsj5nzBOm+2TqAJBhb9cp35Isaq+fbvFXlE\n",
                                                                                         "8ICldVHnZKNPfExnTK5FY6T6yDcjBEMnkJQMEMlMCwmuhbwO7iCDicT5hzdnH6MX\n",
                                                                                         "QreKShgB65c/+cu4mHT3StHQg8kRnpvW1N8CAwEAAaOCAlMwggJPMA4GA1UdDwEB\n",
                                                                                         "/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/\n",
                                                                                         "BAIwADAdBgNVHQ4EFgQUeMQw3IPBaOXfPhNaJ+wtXg3puG0wHwYDVR0jBBgwFoAU\n",
                                                                                         "FC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzAB\n",
                                                                                         "hhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5p\n",
                                                                                         "LmxlbmNyLm9yZy8wIwYDVR0RBBwwGoIYYXBpMS5vY3BwLmNoYXJnaW5nLmNsb3Vk\n",
                                                                                         "MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUH\n",
                                                                                         "AgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB\n",
                                                                                         "9QSB8gDwAHYAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGEMZT8\n",
                                                                                         "+gAABAMARzBFAiEAt1Z1wpuOQxqEICwha69HzjkPRbbFQOqamN/Bn4lMvywCIDbf\n",
                                                                                         "b+KSkG8u8QqcyhJMTBY3liwAk7Gi2LiJjGVeHpKmAHYAejKMVNi3LbYg6jjgUh7p\n",
                                                                                         "hBZwMhOFTTvSK8E6V6NS61IAAAGEMZT9QAAABAMARzBFAiEAvk1Tl2hPxpjRnqxI\n",
                                                                                         "evSxkIpa2QvDt4ASdOLdOVsbIqMCIGFUVMjdkTmKu9kCGcbRHp2CthkQIhMVzyXK\n",
                                                                                         "F05iCTTaMA0GCSqGSIb3DQEBCwUAA4IBAQCRQCvNR+eVFs2eqxgWIKIKxk/7QZD1\n",
                                                                                         "kdpIPuDYoJ/5EDLj1j4jHBiPe4PsIbrPojWnk3XmAtq8EOSVYjspimQjUZMIe3nx\n",
                                                                                         "Q4T+i+siYwUapAfQep8f004EfJRC0xG9p6D1X6bBWmZgSYINM4VCLQ2P6dEv/ZFc\n",
                                                                                         "IQFMw0/Iv6emxDP1mGsOjoeZs86DqPwJBOb5Qn+MNqEh49bkFVPno8SoPDcxHZur\n",
                                                                                         "akYhAo/LuuRLPkfhkhBESsX3dTnvivjkP2nz4M58tHSkZit5y9Zx4NOahnvj4L1J\n",
                                                                                         "cJLtsZ6AwDqdkoVg/i9nqEGOLzYuLDoQsUW9koyP5FM2/qctVi3ZkEzG\n",
                                                                                         "-----END CERTIFICATE-----\n\n"
                                                                                     )));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region DeleteCertificate

                        //   deletecertificate GD002
                        if (command == "deletecertificate"      && commandArray.Length == 2)
                        {

                            var response = await testCSMSv1_6.DeleteCertificate(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                new OCPPv1_6.CertificateHashData(
                                                                                    OCPPv1_6.HashAlgorithms.SHA256,
                                                                                    "bde18ac64b30e7e33c6407fcc625b80a8be4e59000aefe703506d2bf7645f810",
                                                                                    "b44b3ed74a4ce77d54469463bf1042cbd8d0c1981a71febac58b23342fda07b9",
                                                                                    "4E0A1C2E3F1954DB984A276013E335FEE24"
                                                                                ));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region GetInstalledCertificateIds

                        //   getcerts GD002 csrc
                        if (command == "getcerts"               && commandArray.Length == 3 && commandArray[2].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCSMSv1_6.GetInstalledCertificateIds(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                         OCPPv1_6.CertificateUse.CentralSystemRootCertificate);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getcerts GD002 mrc
                        if (command == "getcerts"               && commandArray.Length == 3 && commandArray[2].ToLower() == "mrc".ToLower())
                        {

                            var response = await testCSMSv1_6.GetInstalledCertificateIds(OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                         OCPPv1_6.CertificateUse.ManufacturerRootCertificate);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion

                        #region InstallCertificate

                        //   installcertificate GD002 csrc
                        if (command == "installcertificate"     && commandArray.Length == 3 && commandArray[2].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCSMSv1_6.InstallCertificate(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                 CertificateType:  OCPPv1_6.CertificateUse.CentralSystemRootCertificate,
                                                                                 Certificate:      OCPPv1_6.Certificate.Parse(String.Concat(
                                                                                                       "-----BEGIN CERTIFICATE-----" + "\n",
                                                                                                       "MIIFNjCCBB6gAwIBAgISBOChwuPxlU25hKJ2AT4zX+4kMA0GCSqGSIb3DQEBCwUA" + "\n",
                                                                                                       "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD" + "\n",
                                                                                                       "EwJSMzAeFw0yMjExMDEwNDA1NThaFw0yMzAxMzAwNDA1NTdaMCMxITAfBgNVBAMT" + "\n",
                                                                                                       "GGFwaTEub2NwcC5jaGFyZ2luZy5jbG91ZDCCASIwDQYJKoZIhvcNAQEBBQADggEP" + "\n",
                                                                                                       "ADCCAQoCggEBANXXEPaMYd8g3BmOuNLbJC9j5KHEOQebZ71dQcPGrD5pm8TICEmr" + "\n",
                                                                                                       "PnAVh/TjF61dco/Bw0HjDz+mI62RHe3tBXggN7p7THKTBLcEMXNMYaEIgp+N1GDV" + "\n",
                                                                                                       "4N1ooT9TcnAPID38mjNN/zdPZ2L9IOcE3S9e0AB1a7oJDppvAKIixej+gymuugvy" + "\n",
                                                                                                       "DqwDfugfyFXGpuEXm+xl//D5RjN8Mgsj5nzBOm+2TqAJBhb9cp35Isaq+fbvFXlE" + "\n",
                                                                                                       "8ICldVHnZKNPfExnTK5FY6T6yDcjBEMnkJQMEMlMCwmuhbwO7iCDicT5hzdnH6MX" + "\n",
                                                                                                       "QreKShgB65c/+cu4mHT3StHQg8kRnpvW1N8CAwEAAaOCAlMwggJPMA4GA1UdDwEB" + "\n",
                                                                                                       "/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/" + "\n",
                                                                                                       "BAIwADAdBgNVHQ4EFgQUeMQw3IPBaOXfPhNaJ+wtXg3puG0wHwYDVR0jBBgwFoAU" + "\n",
                                                                                                       "FC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzAB" + "\n",
                                                                                                       "hhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5p" + "\n",
                                                                                                       "LmxlbmNyLm9yZy8wIwYDVR0RBBwwGoIYYXBpMS5vY3BwLmNoYXJnaW5nLmNsb3Vk" + "\n",
                                                                                                       "MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUH" + "\n",
                                                                                                       "AgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB" + "\n",
                                                                                                       "9QSB8gDwAHYAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGEMZT8" + "\n",
                                                                                                       "+gAABAMARzBFAiEAt1Z1wpuOQxqEICwha69HzjkPRbbFQOqamN/Bn4lMvywCIDbf" + "\n",
                                                                                                       "b+KSkG8u8QqcyhJMTBY3liwAk7Gi2LiJjGVeHpKmAHYAejKMVNi3LbYg6jjgUh7p" + "\n",
                                                                                                       "hBZwMhOFTTvSK8E6V6NS61IAAAGEMZT9QAAABAMARzBFAiEAvk1Tl2hPxpjRnqxI" + "\n",
                                                                                                       "evSxkIpa2QvDt4ASdOLdOVsbIqMCIGFUVMjdkTmKu9kCGcbRHp2CthkQIhMVzyXK" + "\n",
                                                                                                       "F05iCTTaMA0GCSqGSIb3DQEBCwUAA4IBAQCRQCvNR+eVFs2eqxgWIKIKxk/7QZD1" + "\n",
                                                                                                       "kdpIPuDYoJ/5EDLj1j4jHBiPe4PsIbrPojWnk3XmAtq8EOSVYjspimQjUZMIe3nx" + "\n",
                                                                                                       "Q4T+i+siYwUapAfQep8f004EfJRC0xG9p6D1X6bBWmZgSYINM4VCLQ2P6dEv/ZFc" + "\n",
                                                                                                       "IQFMw0/Iv6emxDP1mGsOjoeZs86DqPwJBOb5Qn+MNqEh49bkFVPno8SoPDcxHZur" + "\n",
                                                                                                       "akYhAo/LuuRLPkfhkhBESsX3dTnvivjkP2nz4M58tHSkZit5y9Zx4NOahnvj4L1J" + "\n",
                                                                                                       "cJLtsZ6AwDqdkoVg/i9nqEGOLzYuLDoQsUW9koyP5FM2/qctVi3ZkEzG" + "\n",
                                                                                                       "-----END CERTIFICATE-----" + "\n" + "\n"
                                                                                                   )));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   installcertificate GD002 mrc
                        if (command == "installcertificate"     && commandArray.Length == 3 && commandArray[2].ToLower() == "mrc".ToLower())
                        {

                            var response = await testCSMSv1_6.InstallCertificate(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                 CertificateType:  OCPPv1_6.CertificateUse.ManufacturerRootCertificate,
                                                                                 Certificate:      OCPPv1_6.Certificate.Parse(String.Concat(
                                                                                                       "-----BEGIN CERTIFICATE-----" + "\n",
                                                                                                       "MIIFNjCCBB6gAwIBAgISBOChwuPxlU25hKJ2AT4zX+4kMA0GCSqGSIb3DQEBCwUA" + "\n",
                                                                                                       "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD" + "\n",
                                                                                                       "EwJSMzAeFw0yMjExMDEwNDA1NThaFw0yMzAxMzAwNDA1NTdaMCMxITAfBgNVBAMT" + "\n",
                                                                                                       "GGFwaTEub2NwcC5jaGFyZ2luZy5jbG91ZDCCASIwDQYJKoZIhvcNAQEBBQADggEP" + "\n",
                                                                                                       "ADCCAQoCggEBANXXEPaMYd8g3BmOuNLbJC9j5KHEOQebZ71dQcPGrD5pm8TICEmr" + "\n",
                                                                                                       "PnAVh/TjF61dco/Bw0HjDz+mI62RHe3tBXggN7p7THKTBLcEMXNMYaEIgp+N1GDV" + "\n",
                                                                                                       "4N1ooT9TcnAPID38mjNN/zdPZ2L9IOcE3S9e0AB1a7oJDppvAKIixej+gymuugvy" + "\n",
                                                                                                       "DqwDfugfyFXGpuEXm+xl//D5RjN8Mgsj5nzBOm+2TqAJBhb9cp35Isaq+fbvFXlE" + "\n",
                                                                                                       "8ICldVHnZKNPfExnTK5FY6T6yDcjBEMnkJQMEMlMCwmuhbwO7iCDicT5hzdnH6MX" + "\n",
                                                                                                       "QreKShgB65c/+cu4mHT3StHQg8kRnpvW1N8CAwEAAaOCAlMwggJPMA4GA1UdDwEB" + "\n",
                                                                                                       "/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/" + "\n",
                                                                                                       "BAIwADAdBgNVHQ4EFgQUeMQw3IPBaOXfPhNaJ+wtXg3puG0wHwYDVR0jBBgwFoAU" + "\n",
                                                                                                       "FC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzAB" + "\n",
                                                                                                       "hhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5p" + "\n",
                                                                                                       "LmxlbmNyLm9yZy8wIwYDVR0RBBwwGoIYYXBpMS5vY3BwLmNoYXJnaW5nLmNsb3Vk" + "\n",
                                                                                                       "MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUH" + "\n",
                                                                                                       "AgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB" + "\n",
                                                                                                       "9QSB8gDwAHYAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGEMZT8" + "\n",
                                                                                                       "+gAABAMARzBFAiEAt1Z1wpuOQxqEICwha69HzjkPRbbFQOqamN/Bn4lMvywCIDbf" + "\n",
                                                                                                       "b+KSkG8u8QqcyhJMTBY3liwAk7Gi2LiJjGVeHpKmAHYAejKMVNi3LbYg6jjgUh7p" + "\n",
                                                                                                       "hBZwMhOFTTvSK8E6V6NS61IAAAGEMZT9QAAABAMARzBFAiEAvk1Tl2hPxpjRnqxI" + "\n",
                                                                                                       "evSxkIpa2QvDt4ASdOLdOVsbIqMCIGFUVMjdkTmKu9kCGcbRHp2CthkQIhMVzyXK" + "\n",
                                                                                                       "F05iCTTaMA0GCSqGSIb3DQEBCwUAA4IBAQCRQCvNR+eVFs2eqxgWIKIKxk/7QZD1" + "\n",
                                                                                                       "kdpIPuDYoJ/5EDLj1j4jHBiPe4PsIbrPojWnk3XmAtq8EOSVYjspimQjUZMIe3nx" + "\n",
                                                                                                       "Q4T+i+siYwUapAfQep8f004EfJRC0xG9p6D1X6bBWmZgSYINM4VCLQ2P6dEv/ZFc" + "\n",
                                                                                                       "IQFMw0/Iv6emxDP1mGsOjoeZs86DqPwJBOb5Qn+MNqEh49bkFVPno8SoPDcxHZur" + "\n",
                                                                                                       "akYhAo/LuuRLPkfhkhBESsX3dTnvivjkP2nz4M58tHSkZit5y9Zx4NOahnvj4L1J" + "\n",
                                                                                                       "cJLtsZ6AwDqdkoVg/i9nqEGOLzYuLDoQsUW9koyP5FM2/qctVi3ZkEzG" + "\n",
                                                                                                       "-----END CERTIFICATE-----" + "\n" + "\n"
                                                                                                   )));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region GetLog

                        //   getlog GD002 diagnostics
                        if (command == "getlog"                 && commandArray.Length == 3 && commandArray[2].ToLower() == "diagnostics".ToLower())
                        {

                            var response = await testCSMSv1_6.GetLog(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                     LogType:        OCPPv1_6.LogTypes.DiagnosticsLog,
                                                                     LogRequestId:   1,
                                                                     Log:            new OCPPv1_6.LogParameters(
                                                                                         RemoteLocation:   URL.Parse("https://api2.ocpp.charging.cloud:9901"),
                                                                                         OldestTimestamp:  null,
                                                                                         LatestTimestamp:  null
                                                                                     ),
                                                                     Retries:        null,
                                                                     RetryInterval:  null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getlog GD002 security
                        if (command == "getlog"                 && commandArray.Length == 3 && commandArray[2].ToLower() == "security".ToLower())
                        {

                            var response = await testCSMSv1_6.GetLog(ChargeBoxId:    OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                     LogType:        OCPPv1_6.LogTypes.SecurityLog,
                                                                     LogRequestId:   1,
                                                                     Log:            new OCPPv1_6.LogParameters(
                                                                                         RemoteLocation:   URL.Parse("https://api2.ocpp.charging.cloud:9901"),
                                                                                         OldestTimestamp:  null,
                                                                                         LatestTimestamp:  null
                                                                                     ),
                                                                     Retries:        null,
                                                                     RetryInterval:  null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        #endregion


                        #region SignedUpdateFirmware

                        //   signedupdatefirmware GD002 csrc
                        if (command == "signedupdatefirmware"   && commandArray.Length == 3 && commandArray[2].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCSMSv1_6.SignedUpdateFirmware(ChargeBoxId:      OCPPv1_6.ChargeBox_Id.Parse(commandArray[1]),
                                                                                   Firmware:         new OCPPv1_6.FirmwareImage(
                                                                                                         RemoteLocation:      URL.Parse("https://api2.ocpp.charging.cloud:9901/security0001.log"),
                                                                                                         RetrieveTimestamp:   DateTime.UtcNow,
                                                                                                         SigningCertificate:  "xxx",
                                                                                                         Signature:           "yyy"
                                                                                                     ),
                                                                                   UpdateRequestId:  1,
                                                                                   Retries:          null,
                                                                                   RetryInterval:    null);

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
