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

//using OCPPv2_0 = cloud.charging.open.protocols.OCPPv1_6;

#endregion

namespace org.GraphDefined.WWCP.OCPP.Tests
{

    public class Program
    {

        public static void MessageTests()
        {

            #region BootNotification request

            {

                var original = new BootNotificationRequest(ChargeBox_Id.Parse("1"),
                                                           "vendor",
                                                           "model",
                                                           "chargePointSerialnumber",
                                                           "chargeBoxSerialnumber",
                                                           "firmwareVersion",
                                                           "ICCID",
                                                           "IMSI",
                                                           "MeterType",
                                                           "MeterSerialNumber",
                                                           Request_Id.Parse("1234"),
                                                           DateTime.Now);

                var xml = BootNotificationRequest.Parse(original.ToXML().ToString(),
                                                        Request_Id.  Parse("1234"),
                                                        ChargeBox_Id.Parse("1"));

                if (!(original.ChargePointVendor       == xml.ChargePointVendor       &&
                      original.ChargePointModel        == xml.ChargePointModel        &&
                      original.ChargePointSerialNumber == xml.ChargePointSerialNumber &&
                      original.ChargeBoxSerialNumber   == xml.ChargeBoxSerialNumber   &&
                      original.FirmwareVersion         == xml.FirmwareVersion         &&
                      original.Iccid                   == xml.Iccid                   &&
                      original.IMSI                    == xml.IMSI                    &&
                      original.MeterType               == xml.MeterType               &&
                      original.MeterSerialNumber       == xml.MeterSerialNumber))
                {
                    Console.WriteLine("BootNotification request XML test failed!");
                    return;
                }

                var json = BootNotificationRequest.Parse(original.ToJSON().ToString(),
                                                         Request_Id.Parse("1234"),
                                                         ChargeBox_Id.Parse("1"));

                if (!(original.ChargePointVendor       == json.ChargePointVendor       &&
                      original.ChargePointModel        == json.ChargePointModel        &&
                      original.ChargePointSerialNumber == json.ChargePointSerialNumber &&
                      original.ChargeBoxSerialNumber   == json.ChargeBoxSerialNumber   &&
                      original.FirmwareVersion         == json.FirmwareVersion         &&
                      original.Iccid                   == json.Iccid                   &&
                      original.IMSI                    == json.IMSI                    &&
                      original.MeterType               == json.MeterType               &&
                      original.MeterSerialNumber       == json.MeterSerialNumber))
                {
                    Console.WriteLine("BootNotification request JSON test failed!");
                    return;
                }

            }

            #endregion

            #region BootNotification response

            {

                var request   = new BootNotificationRequest(ChargeBox_Id.Parse("1"),
                                                            "vendor",
                                                            "model",
                                                            "chargePointSerialnumber",
                                                            "chargeBoxSerialnumber",
                                                            "firmwareVersion",
                                                            "ICCID",
                                                            "IMSI",
                                                            "MeterType",
                                                            "MeterSerialNumber",
                                                            Request_Id.Parse("1234"),
                                                            DateTime.Now);

                var original  = new BootNotificationResponse(request,
                                                             RegistrationStatus.Accepted,
                                                             DateTime.Parse(DateTime.UtcNow.ToIso8601()).ToUniversalTime(),
                                                             TimeSpan.FromSeconds(120));

                var xml       = BootNotificationResponse.Parse(request, original.ToXML().ToString());

                if (!(original.Status      == xml.Status      &&
                      original.CurrentTime == xml.CurrentTime &&
                      original.HeartbeatInterval    == xml.HeartbeatInterval))
                {
                    Console.WriteLine("BootNotification response XML test failed!");
                    return;
                }

                var json      = BootNotificationResponse.Parse(request, original.ToJSON().ToString());

                if (!(original.Status      == json.Status      &&
                      original.CurrentTime == json.CurrentTime &&
                      original.HeartbeatInterval    == json.HeartbeatInterval))
                {
                    Console.WriteLine("BootNotification response JSON test failed!");
                    return;
                }

            }

            #endregion

        }




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

            var testCentralSystem      = new TestCentralSystem(CentralSystemId:        CentralSystem_Id.Parse("OCPPTest01"),
                                                               RequireAuthentication:  false,
                                                               HTTPUploadPort:         IPPort.Parse(9901),
                                                               DNSClient:              API_DNSClient);

            var testBackendWebSockets  = testCentralSystem.CreateWebSocketService(
                                             TCPPort:    IPPort.Parse(9900),
                                             AutoStart:  true
                                         );

            var TestBackendSOAP        = testCentralSystem.CreateSOAPService(
                                             TCPPort:    IPPort.Parse(8800),
                                             DNSClient:  API_DNSClient,
                                             AutoStart:  true
                                         );

            testCentralSystem.AddBasicAuth("GD001", "1234");

            //MessageTests();




            var chargingStation1  = new TestChargePoint(ChargeBoxId:              ChargeBox_Id.Parse("GD001"),
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

                                                        //HTTPBasicAuth:            new Tuple<String, String>("OLI_001", "1234"),
                                                        //HTTPBasicAuth:            new Tuple<String, String>("GD001", "1234"),
                                                        DNSClient:                API_DNSClient);

            var chargingStation2  = new TestChargePoint(ChargeBoxId:              ChargeBox_Id.Parse("CP002"),
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

                                                        DNSClient:                API_DNSClient);


            //var response1  =  await chargingStation1.ConnectWebSocket("From:GD001",
            //                                                          "To:OCPPTest01",
            //                                                          //URL.Parse("ws://janus1.graphdefined.com:80/"));
            //                                                          URL.Parse("http://127.0.0.1:9900/" + chargingStation1.ChargeBoxId));
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

            //var response1a  = await chargingStation1.SendBootNotification();
            //var response1b  = await chargingStation1.SendHeartbeat();
            //var response1c  = await chargingStation1.SendStatusNotification(Connector_Id.Parse(1), ChargePointStatus.Available, ChargePointErrorCodes.NoError, "info 1", DateTime.UtcNow, "GD", "VEC01");
            //var response1d  = await chargingStation1.TransferData("GD", "Message1", "Data1");
            //var response1e  = await chargingStation1.SendDiagnosticsStatusNotification(DiagnosticsStatus.UploadFailed);
            //var response1f  = await chargingStation1.SendFirmwareStatusNotification(FirmwareStatus.Installed);

            //var response1m  = await chargingStation1.Authorize(IdToken.Parse("000000"));
            //var validToken  = IdToken.Parse("000000");
            //var response1m  = await chargingStation1.Authorize(validToken);

            //if (response1a.Status           == RegistrationStatus. Accepted &&
            //    response1m.IdTagInfo.Status == AuthorizationStatus.Accepted)
            //{

            //    var startTimestamp = DateTime.UtcNow;
            //    var response1n  = await chargingStation1.StartTransaction(Connector_Id.Parse(1), validToken, startTimestamp, 0);

            //    var response1n2 = await chargingStation1.SendStatusNotification(Connector_Id.Parse(1),
            //                                                                    ChargePointStatus.Charging,
            //                                                                    ChargePointErrorCodes.NoError,
            //                                                                    "info 2",
            //                                                                    DateTime.UtcNow,
            //                                                                    "GD",
            //                                                                    "VEC02");

            //    await Task.Delay(10);
            //    var firstTimestamp = DateTime.UtcNow;
            //    var response1o  = await chargingStation1.SendMeterValues (Connector_Id.Parse(1), new MeterValue[] {
            //                                                                                         new MeterValue(startTimestamp,
            //                                                                                                        new SampledValue[] {
            //                                                                                                            new SampledValue("0",
            //                                                                                                                             ReadingContexts.TransactionBegin,
            //                                                                                                                             ValueFormats.Raw,
            //                                                                                                                             Measurands.EnergyActiveImportRegister,
            //                                                                                                                             null,//Phases.L1,
            //                                                                                                                             Locations.Outlet,
            //                                                                                                                             UnitsOfMeasure.kWh),
            //                                                                                                            new SampledValue("0 - but secure!",
            //                                                                                                                             ReadingContexts.TransactionBegin,
            //                                                                                                                             ValueFormats.SignedData,
            //                                                                                                                             Measurands.CurrentImport,
            //                                                                                                                             null,//Phases.L1,
            //                                                                                                                             Locations.Outlet,
            //                                                                                                                             UnitsOfMeasure.kWh)
            //                                                                                                        }),
            //                                                                                         new MeterValue(firstTimestamp,
            //                                                                                                        new SampledValue[] {
            //                                                                                                            new SampledValue("20",
            //                                                                                                                             ReadingContexts.SamplePeriodic,
            //                                                                                                                             ValueFormats.SignedData,
            //                                                                                                                             Measurands.EnergyActiveImportRegister,
            //                                                                                                                             null,//Phases.Unknown,
            //                                                                                                                             Locations.Outlet,
            //                                                                                                                             UnitsOfMeasure.kWh)
            //                                                                                                        })
            //                                                                                     });

            //    await Task.Delay(10);
            //    var stopTimestamp = DateTime.UtcNow;
            //    var response1p  = await chargingStation1.StopTransaction(response1n.TransactionId,
            //                                                             DateTime.Now,
            //                                                             80,
            //                                                             validToken,
            //                                                             Reasons.EVDisconnected,
            //                                                             new MeterValue[] {
            //                                                                 new MeterValue(startTimestamp,
            //                                                                                new SampledValue[] {
            //                                                                                    new SampledValue("0",
            //                                                                                                     ReadingContexts.TransactionBegin,
            //                                                                                                     ValueFormats.Raw,
            //                                                                                                     Measurands.EnergyActiveImportRegister,
            //                                                                                                     null,//Phases.L1,
            //                                                                                                     Locations.Outlet,
            //                                                                                                     UnitsOfMeasure.kWh),
            //                                                                                    new SampledValue("0 kWh - but secure!",
            //                                                                                                     ReadingContexts.TransactionBegin,
            //                                                                                                     ValueFormats.SignedData,
            //                                                                                                     Measurands.EnergyActiveImportRegister,
            //                                                                                                     null,//Phases.L1,
            //                                                                                                     Locations.Outlet,
            //                                                                                                     UnitsOfMeasure.kWh)
            //                                                                                }),
            //                                                                 new MeterValue(firstTimestamp,
            //                                                                                new SampledValue[] {
            //                                                                                    new SampledValue("20",
            //                                                                                                     ReadingContexts.SamplePeriodic,
            //                                                                                                     ValueFormats.Raw,
            //                                                                                                     Measurands.EnergyActiveImportRegister,
            //                                                                                                     null,//Phases.L1,
            //                                                                                                     Locations.Outlet,
            //                                                                                                     UnitsOfMeasure.kWh),
            //                                                                                    new SampledValue("20 kWh - but secure!",
            //                                                                                                     ReadingContexts.SamplePeriodic,
            //                                                                                                     ValueFormats.SignedData,
            //                                                                                                     Measurands.EnergyActiveImportRegister,
            //                                                                                                     null,//Phases.L1,
            //                                                                                                     Locations.Outlet,
            //                                                                                                     UnitsOfMeasure.kWh)
            //                                                                                }),
            //                                                                 new MeterValue(stopTimestamp,
            //                                                                                new SampledValue[] {
            //                                                                                    new SampledValue("40",
            //                                                                                                     ReadingContexts.TransactionEnd,
            //                                                                                                     ValueFormats.Raw,
            //                                                                                                     Measurands.EnergyActiveImportRegister,
            //                                                                                                     null,//Phases.L1,
            //                                                                                                     Locations.Outlet,
            //                                                                                                     UnitsOfMeasure.kWh),
            //                                                                                    new SampledValue("40 kWh - but secure!",
            //                                                                                                     ReadingContexts.TransactionEnd,
            //                                                                                                     ValueFormats.SignedData,
            //                                                                                                     Measurands.EnergyActiveImportRegister,
            //                                                                                                     null,//Phases.L1,
            //                                                                                                     Locations.Outlet,
            //                                                                                                     UnitsOfMeasure.kWh)
            //                                                                                })
            //                                                             });

            //    var response1q = await chargingStation1.SendStatusNotification(Connector_Id.Parse(1), ChargePointStatus.Finishing, ChargePointErrorCodes.NoError, "info 3", DateTime.UtcNow, "GD", "VEC03");
            //    await Task.Delay(10);
            //    var response1r = await chargingStation1.SendStatusNotification(Connector_Id.Parse(1), ChargePointStatus.Available, ChargePointErrorCodes.NoError, "info 4", DateTime.UtcNow, "GD", "VEC04");

            //}

            var xy = 23;


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

            var x = 23;

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

            String[] command = null;

            do
            {

                command = Console.ReadLine()?.Trim()?.Split(' ');

                if (command.SafeAny() && command[0].Length > 0)
                {

                    if (command[0].StartsWith("trigger") && command.Length == 3 && command[2].ToLower() == "BootNotification".ToLower())
                    {
                        var response = await testCentralSystem.TriggerMessage(ChargeBox_Id.Parse(command[1]), MessageTriggers.BootNotification);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("trigger") && command.Length == 3 && command[2].ToLower() == "StatusNotification".ToLower())
                    {
                        var response = await testCentralSystem.TriggerMessage(ChargeBox_Id.Parse(command[1]), MessageTriggers.StatusNotification);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("trigger") && command.Length == 4 && command[3].ToLower() == "MeterValues".ToLower())
                    {
                        var response = await testCentralSystem.TriggerMessage(ChargeBox_Id.Parse(command[1]), MessageTriggers.MeterValues, Connector_Id.Parse(command[2]));
                        Console.WriteLine(response.ToJSON());
                    }


                    if (command[0].StartsWith("hardreset") && command.Length == 2)
                    {
                        var response = await testCentralSystem.Reset(ChargeBox_Id.Parse(command[1]), ResetTypes.Hard);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("softreset") && command.Length == 2)
                    {
                        var response = await testCentralSystem.Reset(ChargeBox_Id.Parse(command[1]), ResetTypes.Soft);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("setinoperative") && command.Length == 3)
                    {
                        var response = await testCentralSystem.ChangeAvailability(ChargeBox_Id.Parse(command[1]), Connector_Id.Parse(command[2]), Availabilities.Inoperative);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("setoperative") && command.Length == 3)
                    {
                        var response = await testCentralSystem.ChangeAvailability(ChargeBox_Id.Parse(command[1]), Connector_Id.Parse(command[2]), Availabilities.Operative);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("getdiag") && command.Length == 3)
                    {
                        var response = await testCentralSystem.GetDiagnostics(ChargeBox_Id.Parse(command[1]), command[2]); // http://95.89.178.27:9901/diagnostics/
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("getconf") && command.Length == 2)
                    {
                        var response = await testCentralSystem.GetConfiguration(ChargeBox_Id.Parse(command[1]));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("getconf") && command.Length > 2)
                    {
                        var response = await testCentralSystem.GetConfiguration(ChargeBox_Id.Parse(command[1]), command.Skip(2));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("changeconfiguration") && command.Length == 4)
                    {
                        var response = await testCentralSystem.ChangeConfiguration(ChargeBox_Id.Parse(command[1]), command[2], command[3]);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("transferdata") && command.Length == 5)
                    {
                        var response = await testCentralSystem.DataTransfer(ChargeBox_Id.Parse(command[1]), command[2], command[3], command[4]);
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("reserve") && command.Length == 5)
                    {
                        var response = await testCentralSystem.ReserveNow(ChargeBox_Id.Parse(command[1]), Connector_Id.Parse(command[2]), Reservation_Id.Parse(command[3]), DateTime.UtcNow + TimeSpan.FromMinutes(15), IdToken.Parse(command[4]));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("cancelrreservation") && command.Length == 3)
                    {
                        var response = await testCentralSystem.CancelReservation(ChargeBox_Id.Parse(command[1]), Reservation_Id.Parse(command[2]));
                        Console.WriteLine(response.ToJSON());
                    }


                    if (command[0].StartsWith("remotestart") && command.Length == 4)
                    {
                        var response = await testCentralSystem.RemoteStartTransaction(ChargeBox_Id.Parse(command[1]), IdToken.Parse(command[2]), Connector_Id.Parse(command[3]));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("remotestop") && command.Length == 3)
                    {
                        var response = await testCentralSystem.RemoteStopTransaction(ChargeBox_Id.Parse(command[1]), Transaction_Id.Parse(command[2]));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("unlock") && command.Length == 3)
                    {
                        var response = await testCentralSystem.UnlockConnector(ChargeBox_Id.Parse(command[1]), Connector_Id.Parse(command[2]));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("getlocallistversion") && command.Length == 2)
                    {
                        var response = await testCentralSystem.GetLocalListVersion(ChargeBox_Id.Parse(command[1]));
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("sendlocallist") && command.Length == 2)
                    {
                        var response = await testCentralSystem.SendLocalList(ChargeBox_Id.Parse(command[1]),
                                                                             0,
                                                                             UpdateTypes.Full,
                                                                             new AuthorizationData[] {
                                                                                 new AuthorizationData(IdToken.Parse("aabbcc11"), new IdTagInfo(AuthorizationStatus.Accepted)),
                                                                                 new AuthorizationData(IdToken.Parse("aabbcc22"), new IdTagInfo(AuthorizationStatus.Accepted)),
                                                                                 new AuthorizationData(IdToken.Parse("aabbcc33"), new IdTagInfo(AuthorizationStatus.Accepted))
                                                                             });
                        Console.WriteLine(response.ToJSON());
                    }

                    if (command[0].StartsWith("clearcache") && command.Length == 2)
                    {
                        var response = await testCentralSystem.ClearCache(ChargeBox_Id.Parse(command[1]));
                        Console.WriteLine(response.ToJSON());
                    }





                    if (command[0] == "s")
                    {

                        //var bb = WSServer.RemoteStartTransaction(ChargeBox_Id.Parse("CP3211"),
                        //                                         IdToken.     Parse("AABBCCDD"),
                        //                                         Connector_Id.Parse(1)).Result;

                        //Console.WriteLine(bb);

                        //var aa = WSServer.Send("CP3211",
                        //                       "TESTACTION",
                        //                       new Newtonsoft.Json.Linq.JObject(new Newtonsoft.Json.Linq.JProperty("prop1", "value1")),
                        //                       DateTime.UtcNow + TimeSpan.FromMinutes(2)).Result;

                    }

                }

            } while (command[0] != "q");

            foreach (var DebugListener in Trace.Listeners)
                (DebugListener as TextWriterTraceListener)?.Flush();

            #endregion

        }

    }

}
