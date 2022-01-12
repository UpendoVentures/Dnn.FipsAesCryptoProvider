/*
----------------------------------------------------------------------------------
 ORIGINAL CODE LICENSE:
----------------------------------------------------------------------------------
Licensed to the .NET Foundation under one or more agreements.
The .NET Foundation licenses this file to you under the MIT license.
See the LICENSE file in the project root for more information

----------------------------------------------------------------------------------
 UPDATED CODE LICENSE:
----------------------------------------------------------------------------------
MIT License

Copyright (c) Upendo Ventures, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System.Web.Security;
using DotNetNuke.Common;

namespace Upendo.Libraries.UpendoProvidersFipsAesCryptoProvider
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    using DotNetNuke.Common.Utilities;
    using DotNetNuke.Instrumentation;
    using DotNetNuke.Services.Cryptography;

    /// <summary>
    /// This library is a FIPS-compliant version of the provider already in DNN, which is not actually FIPS-compliant since it uses the wrong crypto standard.
    /// </summary>
    /// <remarks>
    /// FIPS 197 has required AES encryption since 2001.  
    /// https://csrc.nist.gov/publications/detail/fips/197/final
    /// </remarks>
    internal class FipsAesCompilanceCryptographyProvider : CryptographyProvider
    {
        private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof(FipsAesCompilanceCryptographyProvider));

        private const string p_PassPhrase = "XXXXXXXXXXXXXXXX"; //Q3V98MS9BgNbKwXG
        private const string p_SecureMessage = "(value hidden for security purposes)";
        private const string p_InvalidAttempt = "A decryption attempt was unsuccessful.";
        private const int AesKeySize = 16;

        /// <summary>
        ///     copy of legacy PortalSecurity.Encrypt method.
        /// </summary>
        /// <param name="message">string to be encrypted.</param>
        /// <param name="passphrase">key for encryption.</param>
        /// <returns></returns>
        public override string EncryptParameter(string message, string passphrase)
        {
            if (message == null || message.Length <= 0)
            {
                LogMessage($"{nameof(message)} cannot be empty");
                Requires.NotNullOrEmpty(nameof(message), p_SecureMessage);
            }

            if (passphrase == null || passphrase.Length != AesKeySize)
            {
                LogMessage($"{nameof(passphrase)} must be length of {AesKeySize}");
                Requires.NotNullOrEmpty(nameof(passphrase), p_SecureMessage);
            }

            string value;
            if (!string.IsNullOrEmpty(passphrase))
            {
                // convert key to 16 characters for simplicity
                if (passphrase.Length < AesKeySize)
                {
                    passphrase = passphrase + p_PassPhrase.Substring(0, AesKeySize - passphrase.Length);
                }
                else
                {
                    passphrase = passphrase.Substring(0, AesKeySize);
                }

                // create encryption keys
                byte[] byteKey = Encoding.UTF8.GetBytes(passphrase.Substring(0, AesKeySize));
                byte[] byteVector = Encoding.UTF8.GetBytes(passphrase.Substring(passphrase.Length - AesKeySize, AesKeySize));

                // convert data to byte array
                byte[] byteData = Encoding.UTF8.GetBytes(message);

                // encrypt
                using (var objAes = new AesCryptoServiceProvider())
                using (var objMemoryStream = new MemoryStream())
                using (var objCryptoStream = new CryptoStream(objMemoryStream, objAes.CreateEncryptor(byteKey, byteVector),
                    CryptoStreamMode.Write))
                {
                    objCryptoStream.Write(byteData, 0, byteData.Length);
                    objCryptoStream.FlushFinalBlock();

                    // convert to string and Base64 encode
                    value = Convert.ToBase64String(objMemoryStream.ToArray());
                }
            }
            else
            {
                value = message;
            }

            return value;
        }

        /// <summary>
        ///     copy of legacy PortalSecurity.Decrypt method.
        /// </summary>
        /// <param name="message">string to be decrypted.</param>
        /// <param name="passphrase">key for decryption.</param>
        /// <returns></returns>
        public override string DecryptParameter(string message, string passphrase)
        {
            string strValue = string.Empty;
            if (!string.IsNullOrEmpty(passphrase) && !string.IsNullOrEmpty(message))
            {
                // convert data to byte array and Base64 decode
                try
                {
                    // convert key to 16 characters for simplicity
                    if (passphrase.Length < AesKeySize)
                    {
                        passphrase = passphrase + p_PassPhrase.Substring(0, AesKeySize - passphrase.Length);
                    }
                    else
                    {
                        passphrase = passphrase.Substring(0, AesKeySize);
                    }

                    // create encryption keys
                    byte[] byteKey = Encoding.UTF8.GetBytes(passphrase.Substring(0, AesKeySize));
                    byte[] byteVector = Encoding.UTF8.GetBytes(passphrase.Substring(passphrase.Length - AesKeySize, AesKeySize));
                    byte[] byteData = Convert.FromBase64String(message);

                    // decrypt
                    using (var objAes = new AesCryptoServiceProvider())
                    using (var objMemoryStream = new MemoryStream())
                    using (var objCryptoStream = new CryptoStream(
                        objMemoryStream,
                        objAes.CreateDecryptor(byteKey, byteVector), CryptoStreamMode.Write))
                    {
                        objCryptoStream.Write(byteData, 0, byteData.Length);
                        objCryptoStream.FlushFinalBlock();

                        // convert to string
                        Encoding objEncoding = Encoding.UTF8;
                        strValue = objEncoding.GetString(objMemoryStream.ToArray());
                    }
                }
                catch // decryption error
                {
                    LogInvalidDecryption();
                    strValue = string.Empty;
                }
            }

            return strValue;
        }

        /// <summary>
        ///     copy of legacy PortalSecurity.EncryptString method.
        /// </summary>
        /// <param name="message">string to be encrypted.</param>
        /// <param name="passphrase">key for encryption.</param>
        /// <returns></returns>
        public override string EncryptString(string message, string passphrase)
        {
            if (message == null || message.Length <= 0)
            {
                LogMessage($"{nameof(message)} cannot be empty");
                Requires.NotNullOrEmpty(nameof(message), p_SecureMessage);
            }

            if (passphrase == null || passphrase.Length != AesKeySize)
            {
                LogMessage($"{nameof(passphrase)} must be length of {AesKeySize}");
                Requires.NotNullOrEmpty(nameof(passphrase), p_SecureMessage);
            }

            byte[] results;
            var utf8 = new UTF8Encoding();

            using (var hashProvider = CryptographyUtils.CreateSHA512())
            {
                byte[] taesKey = hashProvider.ComputeHash(utf8.GetBytes(passphrase));
                byte[] trimmedBytes = new byte[24];
                Buffer.BlockCopy(taesKey, 0, trimmedBytes, 0, 24);
                var aesAlgorithm = new AesCryptoServiceProvider
                {
                    Key = trimmedBytes,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7
                };

                byte[] dataToEncrypt = utf8.GetBytes(message);

                try
                {
                    ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor();
                    results = encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
                }
                finally
                {
                    // Clear the AES and Hashprovider services of any sensitive information
                    aesAlgorithm.Clear();
                    hashProvider.Clear();
                }
            }

            // Return the encrypted string as a base64 encoded string
            return Convert.ToBase64String(results);
        }

        /// <summary>
        ///     copy of legacy PortalSecurity.DecryptString method.
        /// </summary>
        /// <param name="message">string to be decrypted.</param>
        /// <param name="passphrase">key for decryption.</param>
        /// <returns></returns>
        public override string DecryptString(string message, string passphrase)
        {
            byte[] results;
            var utf8 = new UTF8Encoding();

            using (var hashProvider = CryptographyUtils.CreateSHA512())
            {
                byte[] taesKey = hashProvider.ComputeHash(utf8.GetBytes(passphrase));
                byte[] trimmedBytes = new byte[24];
                Buffer.BlockCopy(taesKey, 0, trimmedBytes, 0, 24);
                var aesAlgorithm = new AesCryptoServiceProvider
                {
                    Key = trimmedBytes,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7
                };

                byte[] dataToDecrypt = Convert.FromBase64String(message);
                try
                {
                    ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor();
                    results = decryptor.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
                }
                finally
                {
                    // Clear the AES and Hashprovider services of any sensitive information
                    aesAlgorithm.Clear();
                    hashProvider.Clear();
                }
            }

            return utf8.GetString(results);
        }

        #region Logging
        private void LogError(Exception exc)
        {
            try
            {
                if (exc != null)
                {
                    Logger.Error(exc.Message, exc);
                    if (exc.InnerException != null)
                    {
                        LogError(exc.InnerException);
                    }
                }
                DotNetNuke.Services.Exceptions.Exceptions.LogException(exc);
            }
            catch (Exception ex)
            {
                DotNetNuke.Services.Exceptions.Exceptions.LogException(ex);
            }
        }

        private void LogMessage(string message)
        {
            try
            {
                if (!string.IsNullOrEmpty(message))
                {
                    Logger.Error(message);
                }
            }
            catch (Exception ex)
            {
                LogError(ex);
            }
        }

        private void LogInvalidDecryption()
        {
            LogMessage(p_InvalidAttempt);
        }
        #endregion
    }
}
