using System.Text;

namespace CryptoUtility;

public static class SymmetricCipherExtensions
{
    /// <summary>
    /// Encrypts the specified plaintext using the provided cryptographic key.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The cryptographic key used to perform the encryption.</param>
    /// <param name="plaintext">The data to be encrypted.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The resulting encrypted byte array if successful; otherwise, an empty byte array.</description>
    /// </item>
    /// </list>
    /// </returns>
    public static (bool success, byte[] encrypted) Encrypt(
        this ISymmetricCipher cipher,
        byte[] key,
        byte[] plaintext
    )
    {
        if (!LibraryHelper.NotNull(cipher, key, plaintext))
        {
            return (false, Array.Empty<byte>());
        }

        return cipher.Encrypt(key, plaintext, nonce: cipher.GenerateNonce());
    }

    /// <summary>
    /// Encrypts the specified plaintext UTF8 string using the provided Base64 key and returns a Base64-encoded result.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The string representation of the cryptographic key in Base64.</param>
    /// <param name="plaintext">The plaintext UTF8 string to encrypt.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The Base64-encoded encrypted string if successful; otherwise, an empty string.</description>
    /// </item>
    /// </list>
    /// </returns>
    public static (bool success, string encrypted) EncryptBase64(
        this ISymmetricCipher cipher,
        string key,
        string plaintext
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(cipher, key, plaintext))
            {
                return (false, string.Empty);
            }

            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            (bool success, byte[] encrypted) encryptedResult = cipher.Encrypt(
                keyBytes,
                plaintextBytes
            );

            if (!encryptedResult.success)
            {
                return (false, string.Empty);
            }

            string encrypted = Convert.ToBase64String(encryptedResult.encrypted);

            return (true, encrypted);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    /// <summary>
    /// Decrypts the specified Base64-encoded encrypted string using the provided Base64 key and returns the decrypted
    /// plaintext as a Base64 string.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The cryptographic key in Base64 format.</param>
    /// <param name="encrypted">The encrypted data to decrypt in Base64 format.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the decryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>plaintext</c>: The plaintext UTF8 string if successful; otherwise, an empty string.</description>
    /// </item>
    /// </list>
    /// </returns>
    public static (bool success, string plaintext) DecryptBase64(
        this ISymmetricCipher cipher,
        string key,
        string encrypted
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(cipher, key, encrypted))
            {
                return (false, string.Empty);
            }

            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);
            (bool success, byte[] plaintext) decryptedResult = cipher.Decrypt(
                keyBytes,
                encryptedBytes
            );

            if (!decryptedResult.success)
            {
                return (false, string.Empty);
            }

            string plaintext = Encoding.UTF8.GetString(decryptedResult.plaintext);

            return (true, plaintext);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    /// <summary>
    /// Encrypts the specified plaintext using the provided Base64 key and returns the encrypted base64 data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The string representation of the cryptographic key in Base64.</param>
    /// <param name="plaintext">The data to be encrypted.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The encrypted bytes if successful; otherwise, an empty byte array.</description>
    /// </item>
    /// </list>
    /// </returns>
    public static (bool success, byte[] encrypted) EncryptBase64(
        this ISymmetricCipher cipher,
        string key,
        byte[] plaintext
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(cipher, key) || !LibraryHelper.NotNull(plaintext))
            {
                return (false, Array.Empty<byte>());
            }

            byte[] keyBytes = Convert.FromBase64String(key);
            (bool success, byte[] encrypted) encryptedResult = cipher.Encrypt(keyBytes, plaintext);
            return encryptedResult;
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <summary>
    /// Decrypts the specified encrypted data using the provided Base64 cryptographic key and returns the decrypted
    /// plaintext.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The cryptographic key used to perform the decryption.</param>
    /// <param name="encrypted">The encrypted data to decrypt.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the decryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>plaintext</c>: The resulting decrypted byte array if successful; otherwise, an empty byte array.</description>
    /// </item>
    /// </list>
    /// </returns>
    public static (bool success, byte[] plaintext) DecryptBase64(
        this ISymmetricCipher cipher,
        string key,
        byte[] encrypted
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(cipher, key) || !LibraryHelper.NotNull(encrypted))
            {
                return (false, Array.Empty<byte>());
            }

            byte[] keyBytes = Convert.FromBase64String(key);
            (bool success, byte[] plaintext) decryptedResult = cipher.Decrypt(keyBytes, encrypted);
            return decryptedResult;
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public static byte[] GenerateKey(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return Array.Empty<byte>();
        }

        return CryptoHelper.GetBytes(cipher.KeySizeBytes);
    }

    /// <summary>
    /// Generates a new cryptographic nonce for use in encryption or decryption operations.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A byte array containing the generated cryptographic nonce.</returns>
    public static byte[] GenerateNonce(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return Array.Empty<byte>();
        }

        return CryptoHelper.GetBytes(cipher.NonceSizeBytes);
    }

    /// <summary>
    /// Generates a new cryptographic nonce for use in encryption or decryption operations.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A Base64 string containing the generated cryptographic nonce.</returns>
    public static string GenerateNonceBase64(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return string.Empty;
        }

        return Convert.ToBase64String(cipher.GenerateNonce());
    }

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public static string GenerateKeyBase64(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return string.Empty;
        }

        byte[] key = cipher.GenerateKey();
        string result = Convert.ToBase64String(key);
        return result;
    }

    /// <summary>
    /// Verifies the Cipher has all the required parameters for encryption.
    /// </summary>
    /// <param name="key">The key to verify.</param>
    /// <param name="plaintext">The plaintext to verify.</param>
    /// <param name="nonce">The nonce to verify.</param>
    /// <returns>True when the parameters passed verification, false when it fails; missing required parameters.</returns>
    internal static bool VerifyEncryptionParameters(
        this ISymmetricCipher cipher,
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    )
    {
        return LibraryHelper.NotNull(key, plaintext, nonce)
            && key.Length == cipher.KeySizeBytes
            && plaintext.Length > 0
            && nonce.Length == cipher.NonceSizeBytes;
    }

    /// <summary>
    /// Verifies the Cipher has all the required parameters for decryption.
    /// </summary>
    /// <param name="envelope">The cipher envelope to verify.</param>
    /// <returns>True when the parameters passed verification, false when it fails; missing required parameters.</returns>
    internal static bool VerifyDecryptionParametersBase(
        this ISymmetricCipher cipher,
        byte[] key,
        SymmetricCipherEnvelope envelope
    )
    {
        return LibraryHelper.NotNull(key, envelope)
            && key.Length == cipher.KeySizeBytes
            && envelope.Ciphertext.Length > 0
            && envelope.Nonce.Length == cipher.NonceSizeBytes;
    }

    /// <inheritdoc cref="ISymmetricCipher.VerifyDecryptionParameters(byte[], SymmetricCipherEnvelope)"/>
    internal static bool VerifyDecryptionParametersAE(
        this ISymmetricCipherAE cipher,
        byte[] key,
        SymmetricCipherEnvelope envelope
    )
    {
        return LibraryHelper.NotNull(key, envelope)
            && key.Length == cipher.KeySizeBytes
            && envelope.Ciphertext.Length > 0
            && envelope.Nonce.Length == cipher.NonceSizeBytes
            && envelope.Tag.Length == cipher.AuthTagSizeBytes;
    }

    /// <inheritdoc cref="ISymmetricCipher.VerifyDecryptionParameters(byte[], SymmetricCipherEnvelope)"/>
    internal static bool VerifyDecryptionParametersAEAD(
        this ISymmetricCipherAE cipher,
        byte[] key,
        SymmetricCipherEnvelope envelope
    ) => cipher.VerifyDecryptionParametersAE(key, envelope);
}
