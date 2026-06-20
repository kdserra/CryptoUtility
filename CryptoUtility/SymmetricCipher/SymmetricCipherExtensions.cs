using System.Text;

namespace CryptoUtility;

public static class SymmetricCipherExtensions
{
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

    public static byte[] GenerateKey(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return Array.Empty<byte>();
        }

        return CryptoHelper.GetBytes(cipher.KeySizeBytes);
    }

    public static byte[] GenerateNonce(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return Array.Empty<byte>();
        }

        return CryptoHelper.GetBytes(cipher.NonceSizeBytes);
    }

    public static string GenerateNonceBase64(this ISymmetricCipher cipher)
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return string.Empty;
        }

        return Convert.ToBase64String(cipher.GenerateNonce());
    }

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

    internal static bool VerifyDecryptionParametersAEAD(
        this ISymmetricCipherAE cipher,
        byte[] key,
        SymmetricCipherEnvelope envelope
    ) => cipher.VerifyDecryptionParametersAE(key, envelope);
}
