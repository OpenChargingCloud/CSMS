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

using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;

using Org.BouncyCastle.Ocsp;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using OCPPv1_6 = cloud.charging.open.protocols.OCPPv1_6;
using cloud.charging.open.protocols.OCPPv1_6.CS;
using cloud.charging.open.protocols.OCPPv1_6.CP;
using cloud.charging.open.protocols.OCPPv1_6;
using System.Runtime.CompilerServices;
using System.Reflection.Emit;
using com.GraphDefined.SMSApi.API.Response;
using Org.BouncyCastle.Asn1;

//using OCPPv2_0 = cloud.charging.open.protocols.OCPPv1_6;

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


            // Support "gzip" and "deflate" HTTP compression

            var testCentralSystem      = new TestCentralSystem(
                                             CentralSystemId:             CentralSystem_Id.Parse("OCPPTest01"),
                                             RequireAuthentication:       false,
                                             HTTPUploadPort:              IPPort.Parse(9901),
                                             DNSClient:                   API_DNSClient
                                         );

            var testBackendWebSockets  = testCentralSystem.CreateWebSocketService(
                                             TCPPort:                     IPPort.Parse(9900),
                                             //DisableWebSocketPings:       true,
                                             //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                                             Autostart:                   true
                                         );

            //var TestBackendSOAP        = testCentralSystem.CreateSOAPService(
            //                                 TCPPort:    IPPort.Parse(8800),
            //                                 DNSClient:  API_DNSClient,
            //                                 AutoStart:  true
            //                             );

            testCentralSystem.AddHTTPBasicAuth(ChargeBox_Id.Parse("GD001"), "1234");

            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnNewWebSocketConnection += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " new connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tNEW\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnTextMessageRequest     += async (timestamp, server, connection, message, eventTrackingId) => {
                DebugX.Log(String.Concat("Received a web socket TEXT message: '", message, "'!"));
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tIN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", message, Environment.NewLine));
                }
            };

            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnTextMessageSent        += async (timestamp, server, connection, message, eventTrackingId) => {
                DebugX.Log(String.Concat("Sent     a web socket TEXT message: '", message, "'!"));
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tOUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, "\t", message, Environment.NewLine));
                }
            };

            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnCloseMessageReceived += async (timestamp, server, connection, eventTrackingId, ct) => {
                DebugX.Log(String.Concat("HTTP web socket server on ", server.IPSocket, " closed connection with ", connection.TryGetCustomData("chargeBoxId") + " (" + connection.RemoteSocket + ")"));
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tCLOSE\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };





            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnPingMessageReceived += async (timestamp, server, connection, frame, eventTrackingId) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnPingMessageSent     += async (timestamp, server, connection, frame, eventTrackingId) => {
                DebugX.Log(nameof(WebSocketServer) + ": Ping sent:     '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPING OUT\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };

            (testCentralSystem.CentralSystemServers.First() as WebSocketServer).OnPongMessageReceived += async (timestamp, server, connection, frame, eventTrackingId) => {
                DebugX.Log(nameof(WebSocketServer) + ": Pong received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargeBoxId") + ", " + connection.RemoteSocket + ")");
                lock (testCentralSystem)
                {
                    File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
                                       String.Concat(timestamp.ToIso8601(), "\tPONG IN\t", connection.TryGetCustomData("chargeBoxId"), "\t", connection.RemoteSocket, Environment.NewLine));
                }
            };


            var chargingStation1  = new TestChargePoint(
                                        ChargeBoxId:              ChargeBox_Id.Parse("GD001"),
                                        ChargePointVendor:        "GraphDefined",
                                        ChargePointModel:         "VCP.1",
                                        NumberOfConnectors:       2,

                                        Description:              I18NString.Create(Languages.en, "Our first virtual charging station!"),
                                        ChargePointSerialNumber:  "SN-CP0001",
                                        ChargeBoxSerialNumber:    "SN-CB0001",
                                        FirmwareVersion:          "v0.1",
                                        Iccid:                    "0000",
                                        IMSI:                     "1111",
                                        MeterType:                "Virtual Energy Meter",
                                        MeterSerialNumber:        "SN-EN0001",
                                        MeterPublicKey:           "0xcafebabe",

                                        //DisableSendHeartbeats:    true,

                                        //HTTPBasicAuth:            new Tuple<String, String>("OLI_001", "1234"),
                                        //HTTPBasicAuth:            new Tuple<String, String>("GD001", "1234"),
                                        DNSClient:                API_DNSClient
                                    );

            var chargingStation2  = new TestChargePoint(
                                        ChargeBoxId:              ChargeBox_Id.Parse("CP002"),
                                        ChargePointVendor:        "GraphDefined",
                                        ChargePointModel:         "VCP.2",
                                        NumberOfConnectors:       2,

                                        Description:              I18NString.Create(Languages.en, "Our 2nd virtual charging station!"),
                                        ChargePointSerialNumber:  "SN-CP0002",
                                        ChargeBoxSerialNumber:    "SN-CB0002",
                                        FirmwareVersion:          "v0.1",
                                        Iccid:                    "3333",
                                        IMSI:                     "4444",
                                        MeterType:                "Virtual Energy Meter",
                                        MeterSerialNumber:        "SN-EN0002",
                                        MeterPublicKey:           "0xbabecafe",

                                        DNSClient:                API_DNSClient
                                    );


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


            #region SOAP

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


                        // Reset
                        //   hardreset GD002
                        if (command == "hardreset"              && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.Reset(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                         ResetType:    ResetTypes.Hard);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   softreset GD002
                        if (command == "softreset"              && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.Reset(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                         ResetType:    ResetTypes.Soft);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Change Availability
                        //   set inoperative GD002 1
                        if (command == "set"                    && commandArray.Length == 4 && commandArray[1] == "inoperative")
                        {

                            var response = await testCentralSystem.ChangeAvailability(ChargeBoxId:   ChargeBox_Id.Parse(commandArray[2]),
                                                                                      ConnectorId:   Connector_Id.Parse(commandArray[3]),
                                                                                      Availability:  Availabilities.Inoperative);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   set operative GD002 1
                        if (command == "set"                    && commandArray.Length == 4 && commandArray[1] == "operative")
                        {

                            var response = await testCentralSystem.ChangeAvailability(ChargeBoxId:   ChargeBox_Id.Parse(commandArray[2]),
                                                                                      ConnectorId:   Connector_Id.Parse(commandArray[3]),
                                                                                      Availability:  Availabilities.Operative);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Get Configuration
                        //   getconf GD002
                        if (command == "getconf"                && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.GetConfiguration(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getconf GD002 key
                        //   getconf GD002 key1 key2
                        if (command == "getconf"                && commandArray.Length > 2)
                        {

                            var response = await testCentralSystem.GetConfiguration(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                    Keys:         commandArray.Skip(2));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Change Configuration
                        //   setconf GD002 key value
                        if (command == "setconf"                && commandArray.Length == 4)
                        {

                            var response = await testCentralSystem.ChangeConfiguration(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                       Key:          commandArray[2],
                                                                                       Value:        commandArray[3]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Data Transfer
                        //   transferdata GD002 graphdefined
                        if (command == "transferdata"           && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.DataTransfer(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                VendorId:     commandArray[2]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   transferdata GD002 graphdefined message
                        if (command == "transferdata"           && commandArray.Length == 4)
                        {

                            var response = await testCentralSystem.DataTransfer(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                VendorId:     commandArray[2],
                                                                                MessageId:    commandArray[3]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   transferdata GD002 graphdefined message data
                        if (command == "transferdata"           && commandArray.Length == 5)
                        {

                            var response = await testCentralSystem.DataTransfer(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                VendorId:     commandArray[2],
                                                                                MessageId:    commandArray[3],
                                                                                Data:         commandArray[4]);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Get Diagnostics
                        //   getdiag GD002 http://95.89.178.27:9901/diagnostics/
                        if (command == "getdiag"                && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.GetDiagnostics(ChargeBoxId:    ChargeBox_Id.Parse(commandArray[1]),
                                                                                  Location:       commandArray[2],
                                                                                  StartTime:      null,
                                                                                  StopTime:       null,
                                                                                  Retries:        null,
                                                                                  RetryInterval:  null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getdiag GD002 http://95.89.178.27:9901/diagnostics/ 2022-11-08T10:00:00Z 2022-11-12T18:00:00Z 3 30
                        if (command == "getdiag"                && commandArray.Length == 7)
                        {

                            var response = await testCentralSystem.GetDiagnostics(ChargeBoxId:    ChargeBox_Id.Parse(commandArray[1]),
                                                                                  Location:       commandArray[2],
                                                                                  StartTime:      DateTime.Parse(commandArray[3]).ToUniversalTime(),
                                                                                  StopTime:       DateTime.Parse(commandArray[4]).ToUniversalTime(),
                                                                                  Retries:        Byte.Parse(commandArray[5]),
                                                                                  RetryInterval:  TimeSpan.FromSeconds(Byte.Parse(commandArray[6])));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Trigger Message
                        //   trigger GD002 BootNotification
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "BootNotification".ToLower())
                        {

                            var response = await testCentralSystem.TriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                  RequestedMessage:  MessageTriggers.BootNotification);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 DiagnosticsStatusNotification
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "DiagnosticsStatusNotification".ToLower())
                        {

                            var response = await testCentralSystem.TriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                  RequestedMessage:  MessageTriggers.DiagnosticsStatusNotification);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 FirmwareStatusNotification
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "FirmwareStatusNotification".ToLower())
                        {

                            var response = await testCentralSystem.TriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                  RequestedMessage:  MessageTriggers.FirmwareStatusNotification);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 Heartbeat
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "Heartbeat".ToLower())
                        {

                            var response = await testCentralSystem.TriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                  RequestedMessage:  MessageTriggers.Heartbeat);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 MeterValues 1
                        if (command == "trigger"                && commandArray.Length == 4 && commandArray[3].ToLower() == "MeterValues".ToLower())
                        {

                            var response = await testCentralSystem.TriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                  RequestedMessage:  MessageTriggers.MeterValues,
                                                                                  ConnectorId:       Connector_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   trigger GD002 StatusNotification 1
                        if (command == "trigger"                && commandArray.Length == 3 && commandArray[2].ToLower() == "StatusNotification".ToLower())
                        {

                            var response = await testCentralSystem.TriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                  RequestedMessage:  MessageTriggers.StatusNotification,
                                                                                  ConnectorId:       Connector_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Update Firmware
                        //   updatefw GD002 http://95.89.178.27:9901/firmware.bin
                        if (command == "updatefw"               && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.UpdateFirmware(ChargeBoxId:   ChargeBox_Id.Parse(commandArray[1]),
                                                                                  Location:      commandArray[2],
                                                                                  RetrieveDate:  DateTime.UtcNow + TimeSpan.FromHours(3));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        // Reserve Now
                        //   reserve GD002 1 1234 aabbccdd
                        if (command == "reserve"                && commandArray.Length == 5)
                        {

                            var response = await testCentralSystem.ReserveNow(ChargeBoxId:    ChargeBox_Id.  Parse(commandArray[1]),
                                                                              ConnectorId:    Connector_Id.  Parse(commandArray[2]),
                                                                              ReservationId:  Reservation_Id.Parse(commandArray[3]),
                                                                              ExpiryDate:     DateTime.UtcNow + TimeSpan.FromMinutes(15),
                                                                              IdTag:          IdToken.       Parse(commandArray[4]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        // Cancel Reservation
                        //   cancelreservation GD002 1234
                        if (command == "cancelreservation"      && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.CancelReservation(ChargeBoxId:    ChargeBox_Id.  Parse(commandArray[1]),
                                                                                     ReservationId:  Reservation_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Remote Start Transaction
                        //   remotestart GD002 aabbccdd 1
                        if (command == "remotestart"            && commandArray.Length == 4)
                        {

                            var response = await testCentralSystem.RemoteStartTransaction(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                          IdTag:        IdToken.     Parse(commandArray[2]),
                                                                                          ConnectorId:  Connector_Id.Parse(commandArray[3]));;

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Remote Stop Transaction
                        //   remotestop GD002 58378535
                        if (command == "remotestop"             && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.RemoteStopTransaction(ChargeBoxId:    ChargeBox_Id.  Parse(commandArray[1]),
                                                                                         TransactionId:  Transaction_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // SetChargingProfile
                        //   setprofile1 GD002 1
                        if (command == "setprofile1"            && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.SetChargingProfile(ChargeBoxId:      ChargeBox_Id.Parse(commandArray[1]),
                                                                                      ConnectorId:      Connector_Id.Parse(commandArray[2]),
                                                                                      ChargingProfile:  new ChargingProfile(
                                                                                                            ChargingProfile_Id.Parse("100"),
                                                                                                            0,
                                                                                                            ChargingProfilePurposes.TxDefaultProfile,
                                                                                                            ChargingProfileKinds.Recurring,
                                                                                                            new ChargingSchedule(
                                                                                                                ChargingRateUnit:         ChargingRateUnits.Watts,
                                                                                                                ChargingSchedulePeriods:  new ChargingSchedulePeriod[] {
                                                                                                                                              new ChargingSchedulePeriod(
                                                                                                                                                  StartPeriod:   0,       // == 00:00 Uhr
                                                                                                                                                  Limit:         11000,
                                                                                                                                                  NumberPhases:  3
                                                                                                                                              ),
                                                                                                                                              new ChargingSchedulePeriod(
                                                                                                                                                  StartPeriod:   28800,   // == 08:00 Uhr
                                                                                                                                                  Limit:         6000,
                                                                                                                                                  NumberPhases:  3
                                                                                                                                              ),
                                                                                                                                              new ChargingSchedulePeriod(
                                                                                                                                                  StartPeriod:   72000,   // == 20:00 Uhr
                                                                                                                                                  Limit:         11000,
                                                                                                                                                  NumberPhases:  3
                                                                                                                                              )
                                                                                                                                          },
                                                                                                                Duration:                 TimeSpan.FromHours(24),
                                                                                                                StartSchedule:            DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime()

                                                                                                            ),
                                                                                                            Transaction_Id.TryParse("5678"),
                                                                                                            RecurrencyKinds.Daily,
                                                                                                            DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime(),
                                                                                                            DateTime.Parse("2022-12-01T00:00:00Z").ToUniversalTime()
                                                                                                        ));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   setprofile2 GD002 1
                        if (command == "setprofile2"            && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.SetChargingProfile(ChargeBoxId:      ChargeBox_Id.Parse(commandArray[1]),
                                                                                      ConnectorId:      Connector_Id.Parse(commandArray[2]),
                                                                                      ChargingProfile:  new ChargingProfile(
                                                                                                            ChargingProfile_Id.Parse("100"),
                                                                                                            0,
                                                                                                            ChargingProfilePurposes.TxDefaultProfile,
                                                                                                            ChargingProfileKinds.Recurring,
                                                                                                            new ChargingSchedule(
                                                                                                                ChargingRateUnit:         ChargingRateUnits.Watts,
                                                                                                                ChargingSchedulePeriods:  new ChargingSchedulePeriod[] {
                                                                                                                                              new ChargingSchedulePeriod(
                                                                                                                                                  StartPeriod:   0,       // == 00:00 Uhr
                                                                                                                                                  Limit:         11000,
                                                                                                                                                  NumberPhases:  3
                                                                                                                                              ),
                                                                                                                                              new ChargingSchedulePeriod(
                                                                                                                                                  StartPeriod:   21600,   // == 06:00 Uhr
                                                                                                                                                  Limit:         10000,
                                                                                                                                                  NumberPhases:  3
                                                                                                                                              ),
                                                                                                                                              new ChargingSchedulePeriod(
                                                                                                                                                  StartPeriod:   75600,   // == 21:00 Uhr
                                                                                                                                                  Limit:         11000,
                                                                                                                                                  NumberPhases:  3
                                                                                                                                              )
                                                                                                                                          },
                                                                                                                Duration:                 TimeSpan.FromHours(24),
                                                                                                                StartSchedule:            DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime()

                                                                                                            ),
                                                                                                            Transaction_Id.TryParse("5678"),
                                                                                                            RecurrencyKinds.Daily,
                                                                                                            DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime(),
                                                                                                            DateTime.Parse("2022-12-01T00:00:00Z").ToUniversalTime()
                                                                                                        ));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // ClearChargingProfile
                        //   clearprofile GD002 1 100
                        if (command == "clearprofile"           && commandArray.Length >= 2)
                        {

                            var response = await testCentralSystem.ClearChargingProfile(ChargeBoxId:        ChargeBox_Id.Parse(commandArray[1]),
                                                                                        ChargingProfileId:  commandArray.Length >= 4 ? ChargingProfile_Id.Parse(commandArray[3]) : null,
                                                                                        ConnectorId:        commandArray.Length >= 3 ? Connector_Id.      Parse(commandArray[2]) : null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // GetCompositeSchedule
                        //   clearprofile GD002 1 3600
                        if (command == "getschedule"            && commandArray.Length == 4)
                        {

                            var response = await testCentralSystem.GetCompositeSchedule(ChargeBoxId:  ChargeBox_Id.               Parse(commandArray[1]),
                                                                                        ConnectorId:  Connector_Id.               Parse(commandArray[2]),
                                                                                        Duration:     TimeSpan.FromSeconds(UInt32.Parse(commandArray[3])));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // Unlock Connector
                        //   unlock GD002 1
                        if (command == "unlock"                 && commandArray.Length == 3)
                        {

                            var response = await testCentralSystem.UnlockConnector(ChargeBoxId:  ChargeBox_Id.Parse(commandArray[1]),
                                                                                   ConnectorId:  Connector_Id.Parse(commandArray[2]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        // GetLocalListVersion
                        //   getlocallistversion GD002
                        if (command == "getlocallistversion"    && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.GetLocalListVersion(ChargeBox_Id.Parse(commandArray[1]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        // SendLocalList
                        //   sendlocallist GD002
                        if (command == "sendlocallist"          && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.SendLocalList(ChargeBox_Id.Parse(commandArray[1]),
                                                                                 0,
                                                                                 UpdateTypes.Full,
                                                                                 new AuthorizationData[] {
                                                                                     new AuthorizationData(IdToken.Parse("aabbcc11"), new IdTagInfo(AuthorizationStatus.Accepted)),
                                                                                     new AuthorizationData(IdToken.Parse("aabbcc22"), new IdTagInfo(AuthorizationStatus.Accepted)),
                                                                                     new AuthorizationData(IdToken.Parse("aabbcc33"), new IdTagInfo(AuthorizationStatus.Accepted)),
                                                                                     new AuthorizationData(IdToken.Parse("aabbcc44"), new IdTagInfo(AuthorizationStatus.Blocked))
                                                                                 });

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        // ClearCache
                        //   clearcache GD002
                        if (command == "clearcache"             && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.ClearCache(ChargeBox_Id.Parse(commandArray[1]));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }



                        // CertificateSigned
                        //   certificatesigned GD002
                        if (command == "certificatesigned"      && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.CertificateSigned(ChargeBox_Id.Parse(commandArray[1]),
                                                                                     "xxx");

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // DeleteCertificate
                        //   deletecertificate GD002
                        if (command == "deletecertificate"      && commandArray.Length == 2)
                        {

                            var response = await testCentralSystem.DeleteCertificate(ChargeBox_Id.Parse(commandArray[1]),
                                                                                     new CertificateHashData(
                                                                                         HashAlgorithms.SHA256,
                                                                                         "xxx",
                                                                                         "yyy",
                                                                                         "123"
                                                                                     ));

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // ExtendedTriggerMessage
                        //   extendedtrigger GD002 Heartbeat
                        if (command == "extendedtrigger"        && commandArray.Length == 3 && commandArray[2].ToLower() == "Heartbeat".ToLower())
                        {

                            var response = await testCentralSystem.ExtendedTriggerMessage(ChargeBoxId:       ChargeBox_Id.Parse(commandArray[1]),
                                                                                          RequestedMessage:  MessageTriggers.Heartbeat);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // GetInstalledCertificateIds
                        //   getcerts GD002 csrc
                        if (command == "getcerts"               && commandArray.Length == 3 && commandArray[2].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCentralSystem.GetInstalledCertificateIds(ChargeBoxId: ChargeBox_Id.Parse(commandArray[1]),
                                                                                              CertificateUse.CentralSystemRootCertificate);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   getcerts GD002 mrc
                        if (command == "getcerts"               && commandArray.Length == 3 && commandArray[2].ToLower() == "mrc".ToLower())
                        {

                            var response = await testCentralSystem.GetInstalledCertificateIds(ChargeBoxId: ChargeBox_Id.Parse(commandArray[1]),
                                                                                              CertificateUse.ManufacturerRootCertificate);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // GetLog
                        //   getlog GD002 diagnostics
                        if (command == "getlog"                 && commandArray.Length == 3 && commandArray[2].ToLower() == "diagnostics".ToLower())
                        {

                            var response = await testCentralSystem.GetLog(ChargeBoxId:    ChargeBox_Id.Parse(commandArray[1]),
                                                                          LogType:        LogTypes.DiagnosticsLog,
                                                                          LogRequestId:   1,
                                                                          Log:            new LogParameters(
                                                                                              RemoteLocation:   URL.Parse("https://api2.ocpp.charging.cloud:9901/diagnostics0001.log"),
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

                            var response = await testCentralSystem.GetLog(ChargeBoxId:    ChargeBox_Id.Parse(commandArray[1]),
                                                                          LogType:        LogTypes.SecurityLog,
                                                                          LogRequestId:   1,
                                                                          Log:            new LogParameters(
                                                                                              RemoteLocation:   URL.Parse("https://api2.ocpp.charging.cloud:9901/security0001.log"),
                                                                                              OldestTimestamp:  null,
                                                                                              LatestTimestamp:  null
                                                                                          ),
                                                                          Retries:        null,
                                                                          RetryInterval:  null);

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // InstallCertificate
                        //   installcertificate GD002 csrc
                        if (command == "installcertificate"     && commandArray.Length == 3 && commandArray[2].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCentralSystem.InstallCertificate(ChargeBoxId:      ChargeBox_Id.Parse(commandArray[1]),
                                                                                      CertificateType:  CertificateUse.CentralSystemRootCertificate,
                                                                                      Certificate:      "xxx");

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }

                        //   installcertificate GD002 mrc
                        if (command == "installcertificate"     && commandArray.Length == 3 && commandArray[2].ToLower() == "mrc".ToLower())
                        {

                            var response = await testCentralSystem.InstallCertificate(ChargeBoxId:      ChargeBox_Id.Parse(commandArray[1]),
                                                                                      CertificateType:  CertificateUse.ManufacturerRootCertificate,
                                                                                      Certificate:      "xxx");

                            Console.WriteLine(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                            Console.WriteLine(response.ToJSON());

                        }


                        // SignedUpdateFirmware
                        //   signedupdatefirmware GD002 csrc
                        if (command == "signedupdatefirmware" && commandArray.Length == 3 && commandArray[2].ToLower() == "csrc".ToLower())
                        {

                            var response = await testCentralSystem.SignedUpdateFirmware(ChargeBoxId:      ChargeBox_Id.Parse(commandArray[1]),
                                                                                        Firmware:         new FirmwareImage(
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



                    }

                }

            } while (!quit);

            foreach (var DebugListener in Trace.Listeners)
                (DebugListener as TextWriterTraceListener)?.Flush();

            #endregion

        }

    }

}
