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

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.CSMS.Configuration
{

    /// <summary>
    /// Everything this CSMS can be told in writing beyond what every node
    /// can: one document with one section per thing that can be configured.
    /// </summary>
    /// <remarks>
    /// One file rather than one per subject, because these settings are read
    /// together, changed together and backed up together - and because the
    /// question "what is this CSMS configured as" should have one answer
    /// that fits on a screen instead of a directory to go through. The
    /// sections every node has - "dns", "nts" and "certificates" - are in the
    /// same file and are the node's to read; this passes them over, as the
    /// node passes over these.
    ///
    /// Every section is optional and so is every field inside it. A section
    /// that is absent is not a section set to nothing: it means the file has no
    /// opinion, and whatever the CSMS was handed at construction stands.
    /// A CSMS handed nothing either falls back to the system default. So
    /// the order is: system default, then what the constructor was given, then
    /// what this file says - each one only where it actually speaks.
    /// </remarks>
    /// <param name="OCPP">Who this CSMS says it is when it speaks OCPP.</param>
    /// <param name="OCPPServer">The server the charging stations below it connect to.</param>
    /// <param name="OCPI">Who this CSMS is when it speaks OCPI to its roaming partners.</param>
    public sealed record CSMSConfiguration(OCPPConfiguration?        OCPP         = null,
                                           OCPPServerConfiguration?  OCPPServer   = null,
                                           OCPIConfiguration?        OCPI         = null)
    {

        #region Properties

        /// <summary>
        /// Whether this document says anything at all.
        /// </summary>
        public Boolean IsEmpty
            => OCPP is null && OCPPServer is null && OCPI is null;

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The whole document, or the one sentence that says what is wrong with it.
        /// </summary>
        /// <remarks>
        /// A section of the wrong kind is an error rather than a section
        /// skipped: <c>"dns": null</c> is a file that has nothing to say about
        /// DNS, but <c>"dns": "google"</c> is a file whose author believed they
        /// had configured something.
        ///
        /// Sections this CSMS does not know are passed over without a word -
        /// the node's own among them, which the node below has read already. A
        /// file written by a newer CSMS should still start an older one, and
        /// the file keeps them - see <see cref="WWCPConfigFile.TryReplaceSection"/>.
        /// </remarks>
        public static Boolean TryParse(JObject                                    JSON,
                                       [NotNullWhen(true)]  out CSMSConfiguration?  Configuration,
                                       [NotNullWhen(false)] out String?             Error)
        {

            Configuration  = null;
            Error          = null;

            #region OCPP

            OCPPConfiguration? ocpp = null;

            if (JSON[OCPPConfiguration.SectionName] is JToken ocppToken && ocppToken.Type != JTokenType.Null)
            {

                if (ocppToken is not JObject ocppJSON)
                {
                    Error = $"'{OCPPConfiguration.SectionName}' must be a JSON object.";
                    return false;
                }

                if (!OCPPConfiguration.TryParse(ocppJSON, out ocpp, out Error))
                    return false;

            }

            #endregion

            #region OCPP server

            OCPPServerConfiguration? ocppServer = null;

            if (JSON[OCPPServerConfiguration.SectionName] is JToken ocppServerToken && ocppServerToken.Type != JTokenType.Null)
            {

                if (ocppServerToken is not JObject ocppServerJSON)
                {
                    Error = $"'{OCPPServerConfiguration.SectionName}' must be a JSON object.";
                    return false;
                }

                if (!OCPPServerConfiguration.TryParse(ocppServerJSON, out ocppServer, out Error))
                    return false;

            }

            #endregion

            #region OCPI

            OCPIConfiguration? ocpi = null;

            if (JSON[OCPIConfiguration.SectionName] is JToken ocpiToken && ocpiToken.Type != JTokenType.Null)
            {

                if (ocpiToken is not JObject ocpiJSON)
                {
                    Error = $"'{OCPIConfiguration.SectionName}' must be a JSON object.";
                    return false;
                }

                if (!OCPIConfiguration.TryParse(ocpiJSON, out ocpi, out Error))
                    return false;

            }

            #endregion

            Configuration = new CSMSConfiguration(ocpp, ocppServer, ocpi);
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The document as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (OCPP is not null)
                json.Add(OCPPConfiguration.SectionName,  OCPP.ToJSON());

            if (OCPPServer is not null)
                json.Add(OCPPServerConfiguration.SectionName, OCPPServer.ToJSON());

            if (OCPI is not null)
                json.Add(OCPIConfiguration.SectionName,  OCPI.ToJSON());

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => IsEmpty
                   ? "nothing configured"
                   : String.Join(", ",
                         new[] {
                             OCPP       is not null ? OCPP.ToString()        : null,
                             OCPPServer is not null ? OCPPServer.ToString()  : null,
                             OCPI       is not null ? OCPI.ToString()        : null
                         }.Where(section => section is not null));

        #endregion

    }

}
