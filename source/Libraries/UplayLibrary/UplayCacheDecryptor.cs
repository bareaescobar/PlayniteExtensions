using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace UplayLibrary
{
    /// <summary>
    /// Decrypts the Ubisoft Connect ".vdat" cache files introduced with the October 2026 client.
    ///
    /// Format of a .vdat file (protobuf wire format):
    ///   field 1 (message): envelope
    ///     field 1 (message): header
    ///       field 1 (varint):  format version (observed: 1)
    ///       field 2 (message): crypto info
    ///         field 1 (varint):  algorithm id (observed: 1 = AES-256-GCM)
    ///         field 2 (string):  key id (32 hex chars) -> names the key blob in the "store" folder
    ///         field 3 (bytes):   nonce  (12 bytes)
    ///         field 4 (bytes):   auth tag (16 bytes)
    ///     field 2 (bytes): ciphertext
    ///
    /// The AES-256 key lives at:
    ///   %LOCALAPPDATA%\Ubisoft Game Launcher\store\&lt;keyId&gt;.bin
    /// protected with Windows DPAPI (current user scope). Once decrypted, the plaintext is
    /// the same protobuf payload the old plain "configurations"/"ownership" files contained.
    /// </summary>
    public static class UplayCacheDecryptor
    {
        private static string StorePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Ubisoft Game Launcher",
            "store");

        /// <summary>
        /// Reads an encrypted .vdat file and returns the decrypted protobuf payload.
        /// </summary>
        public static byte[] DecryptFile(string vdatPath)
        {
            var raw = File.ReadAllBytes(vdatPath);
            var env = ParseEnvelope(raw);

            var keyBlobPath = Path.Combine(StorePath, env.KeyId + ".bin");
            if (!File.Exists(keyBlobPath))
            {
                throw new FileNotFoundException(
                    "Ubisoft Connect key store not found for key id " + env.KeyId, keyBlobPath);
            }

            var protectedKey = File.ReadAllBytes(keyBlobPath);
            var key = ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
            try
            {
                return AesGcmDecrypt(key, env.Nonce, env.Ciphertext, env.Tag);
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
            }
        }

        private class Envelope
        {
            public string KeyId;
            public byte[] Nonce;
            public byte[] Tag;
            public byte[] Ciphertext;
        }

        private static Envelope ParseEnvelope(byte[] data)
        {
            var env = new Envelope();
            int pos = 0;

            // root: field 1, wiretype 2 (length-delimited message)
            var rootField = ReadField(data, ref pos);
            if (rootField.Number != 1 || rootField.WireType != 2)
            {
                throw new InvalidDataException("Unexpected Ubisoft cache root field.");
            }

            int rootEnd = pos + (int)rootField.Length;
            while (pos < rootEnd)
            {
                var f = ReadField(data, ref pos);
                if (f.Number == 1 && f.WireType == 2)
                {
                    // header message
                    ParseHeader(data, pos, pos + (int)f.Length, env);
                    pos += (int)f.Length;
                }
                else if (f.Number == 2 && f.WireType == 2)
                {
                    // ciphertext
                    env.Ciphertext = new byte[f.Length];
                    Array.Copy(data, pos, env.Ciphertext, 0, (int)f.Length);
                    pos += (int)f.Length;
                }
                else
                {
                    SkipField(data, ref pos, f);
                }
            }

            if (env.KeyId == null || env.Nonce == null || env.Tag == null || env.Ciphertext == null)
            {
                throw new InvalidDataException("Ubisoft cache envelope is missing required fields.");
            }

            return env;
        }

        private static void ParseHeader(byte[] data, int pos, int end, Envelope env)
        {
            while (pos < end)
            {
                var f = ReadField(data, ref pos);
                if (f.Number == 2 && f.WireType == 2)
                {
                    // crypto info message
                    ParseCryptoInfo(data, pos, pos + (int)f.Length, env);
                    pos += (int)f.Length;
                }
                else
                {
                    SkipField(data, ref pos, f);
                }
            }
        }

        private static void ParseCryptoInfo(byte[] data, int pos, int end, Envelope env)
        {
            while (pos < end)
            {
                var f = ReadField(data, ref pos);
                if (f.Number == 2 && f.WireType == 2)
                {
                    env.KeyId = Encoding.ASCII.GetString(data, pos, (int)f.Length);
                    pos += (int)f.Length;
                }
                else if (f.Number == 3 && f.WireType == 2)
                {
                    env.Nonce = new byte[f.Length];
                    Array.Copy(data, pos, env.Nonce, 0, (int)f.Length);
                    pos += (int)f.Length;
                }
                else if (f.Number == 4 && f.WireType == 2)
                {
                    env.Tag = new byte[f.Length];
                    Array.Copy(data, pos, env.Tag, 0, (int)f.Length);
                    pos += (int)f.Length;
                }
                else
                {
                    SkipField(data, ref pos, f);
                }
            }
        }

        private struct FieldHeader
        {
            public int Number;
            public int WireType;
            public ulong Length; // only meaningful for wiretype 2
        }

        private static FieldHeader ReadField(byte[] data, ref int pos)
        {
            ulong tag = ReadVarint(data, ref pos);
            var fh = new FieldHeader
            {
                Number = (int)(tag >> 3),
                WireType = (int)(tag & 0x7)
            };
            if (fh.WireType == 2)
            {
                fh.Length = ReadVarint(data, ref pos);
            }
            return fh;
        }

        private static void SkipField(byte[] data, ref int pos, FieldHeader f)
        {
            switch (f.WireType)
            {
                case 0: // varint
                    ReadVarint(data, ref pos);
                    break;
                case 1: // 64-bit
                    pos += 8;
                    break;
                case 2: // length-delimited
                    pos += (int)f.Length;
                    break;
                case 5: // 32-bit
                    pos += 4;
                    break;
                default:
                    throw new InvalidDataException("Unsupported protobuf wire type " + f.WireType);
            }
        }

        private static ulong ReadVarint(byte[] data, ref int pos)
        {
            ulong result = 0;
            int shift = 0;
            while (true)
            {
                byte b = data[pos++];
                result |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    break;
                }
                shift += 7;
            }
            return result;
        }

        #region AES-GCM via Windows CNG (BCrypt)

        // .NET Framework 4.6.2 has no managed AesGcm, so call the Windows CNG API directly.

        private static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
        {
            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            try
            {
                Check(BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0), "BCryptOpenAlgorithmProvider");

                var chainMode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM + "\0");
                Check(BCryptSetProperty(hAlg, "ChainingMode", chainMode, chainMode.Length, 0), "BCryptSetProperty");

                Check(BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0),
                    "BCryptGenerateSymmetricKey");

                var plaintext = new byte[ciphertext.Length];
                var nonceCopy = (byte[])nonce.Clone();
                var tagCopy = (byte[])tag.Clone();

                var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                var nonceHandle = GCHandle.Alloc(nonceCopy, GCHandleType.Pinned);
                var tagHandle = GCHandle.Alloc(tagCopy, GCHandleType.Pinned);
                try
                {
                    authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                    authInfo.dwInfoVersion = 1;
                    authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
                    authInfo.cbNonce = nonceCopy.Length;
                    authInfo.pbTag = tagHandle.AddrOfPinnedObject();
                    authInfo.cbTag = tagCopy.Length;

                    int status = BCryptDecrypt(
                        hKey,
                        ciphertext, ciphertext.Length,
                        ref authInfo,
                        IntPtr.Zero, 0,
                        plaintext, plaintext.Length,
                        out int cbResult,
                        0);

                    if (status != 0)
                    {
                        // STATUS_AUTH_TAG_MISMATCH = 0xC000A002
                        if ((uint)status == 0xC000A002)
                        {
                            throw new CryptographicException(
                                "Ubisoft cache authentication tag mismatch (wrong key or corrupt data).");
                        }
                        throw new CryptographicException("BCryptDecrypt failed with status 0x" + status.ToString("X8"));
                    }

                    if (cbResult != plaintext.Length)
                    {
                        var trimmed = new byte[cbResult];
                        Array.Copy(plaintext, trimmed, cbResult);
                        return trimmed;
                    }
                    return plaintext;
                }
                finally
                {
                    nonceHandle.Free();
                    tagHandle.Free();
                }
            }
            finally
            {
                if (hKey != IntPtr.Zero) { BCryptDestroyKey(hKey); }
                if (hAlg != IntPtr.Zero) { BCryptCloseAlgorithmProvider(hAlg, 0); }
            }
        }

        private static void Check(int status, string what)
        {
            if (status != 0)
            {
                throw new CryptographicException(what + " failed with status 0x" + status.ToString("X8"));
            }
        }

        private const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(
            out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(
            IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(
            IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject,
            byte[] pbSecret, int cbSecret, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(
            IntPtr hKey,
            byte[] pbInput, int cbInput,
            ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
            IntPtr pbIV, int cbIV,
            byte[] pbOutput, int cbOutput,
            out int pcbResult,
            int dwFlags);

        #endregion
    }
}
