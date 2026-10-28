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

using cloud.charging.open.protocols.WWCP.Node;

#endregion

namespace cloud.charging.open.CSMS.Web
{

    /// <summary>
    /// Writing a file that only its owner may read.
    /// </summary>
    /// <remarks>
    /// What is written this way here is private keys and passwords: the OCPP
    /// server key this CSMS listens with, which is the whole of its identity
    /// to every charging station on the site, and the charging stations'
    /// logins.
    ///
    /// <b>The restriction goes on before the content and not afterwards.</b>
    /// Creating a file readable and restricting it once the content is in
    /// leaves a window, and the window is exactly as long as the writing. On
    /// Unix the mode is given at creation; on Windows the file gets
    /// <see cref="OwnerOnly"/>'s protected access control list while it is
    /// still empty - nothing inherited from the folder above, which at the
    /// root of a drive grants every authenticated user.
    /// </remarks>
    public static class OwnerOnlyFile
    {

        #region Write(Path, Content, Complain = null)

        /// <summary>
        /// Writes a file readable and writable by its owner alone: 0600 on
        /// Unix, and on Windows its owner, SYSTEM and the administrators.
        /// </summary>
        /// <param name="Path">The file.</param>
        /// <param name="Content">What goes into it.</param>
        /// <param name="Complain">Told what could not be restricted, and why - a file system that knows neither, say. The file is written all the same.</param>
        public static void Write(String           Path,
                                 String           Content,
                                 Action<String>?  Complain   = null)
        {

            using var stream = File.Open(Path,
                                         OperatingSystem.IsWindows()
                                             ? new FileStreamOptions {
                                                   Mode            = FileMode.Create,
                                                   Access          = FileAccess.Write
                                               }
                                             : new FileStreamOptions {
                                                   Mode            = FileMode.Create,
                                                   Access          = FileAccess.Write,
                                                   UnixCreateMode  = UnixFileMode.UserRead | UnixFileMode.UserWrite
                                               });

            // Still empty here. On Windows this is the restriction; on Unix it
            // is for a file that was there before, which keeps the mode it had.
            OwnerOnly.File(Path, Complain);

            using var writer = new StreamWriter(stream);

            writer.Write(Content);

        }

        #endregion

    }

}
