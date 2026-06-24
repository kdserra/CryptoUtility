using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class AsymmetricCipherExtensions
{
    public static string EncryptBase64(
        this IAsymmetricCipher cipher,
        string publicKeyBase64,
        string plaintextUtf8
    )
    {
        byte[] publicKeyBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
            encryptedBytes = cipher.Encrypt(publicKeyBytes, plaintextBytes);

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this IAsymmetricCipher cipher,
        string secretKeyBase64,
        string encryptedBase64
    )
    {
        byte[] secretKeyBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] decryptedBytes = Array.Empty<byte>();
        string plaintext = string.Empty;

        try
        {
            secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
            encryptedBytes = Convert.FromBase64String(encryptedBase64);
            decryptedBytes = cipher.Decrypt(secretKeyBytes, encryptedBytes);

            plaintext = Encoding.UTF8.GetString(decryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKeyBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(decryptedBytes);
        }

        return plaintext;
    }

    public static (string publicKeyBase64, string secretKeyBase64) GenerateKeyPairBase64(
        this IAsymmetricCipher cipher
    )
    {
        byte[] publicKeyBytes = Array.Empty<byte>();
        byte[] secretKeyBytes = Array.Empty<byte>();
        string publicKeyBase64 = string.Empty;
        string secretKeyBase64 = string.Empty;

        try
        {
            (publicKeyBytes, secretKeyBytes) = cipher.GenerateKeyPair();

            publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
            secretKeyBase64 = Convert.ToBase64String(secretKeyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
            CryptographicOperations.ZeroMemory(secretKeyBytes);
        }

        return (publicKeyBase64, secretKeyBase64);
    }

    public static byte[] HybridEncrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] publicKey,
        byte[] plaintext
    )
    {
        byte[] asymmetricPlaintextDataEncryptionKey = Array.Empty<byte>();
        byte[] asymmetricEncrypted = Array.Empty<byte>();
        byte[] symmetricEncrypted = Array.Empty<byte>();
        byte[] envelopeBytes = Array.Empty<byte>();

        try
        {
            asymmetricPlaintextDataEncryptionKey = symmetricCipher.GenerateKey();

            asymmetricEncrypted = asymmetricCipher.Encrypt(
                publicKey,
                asymmetricPlaintextDataEncryptionKey
            );

            symmetricEncrypted = symmetricCipher.Encrypt(
                asymmetricPlaintextDataEncryptionKey,
                plaintext
            );

            HybridCipherEnvelope envelope = new(
                asymmetricEncrypted,
                symmetricEncrypted
            );

            envelopeBytes = envelope.ToBytes();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(asymmetricPlaintextDataEncryptionKey);
            CryptographicOperations.ZeroMemory(asymmetricEncrypted);
            CryptographicOperations.ZeroMemory(symmetricEncrypted);
        }

        return envelopeBytes;
    }

    public static byte[] HybridDecrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] secretKey,
        byte[] encrypted
    )
    {
        HybridCipherEnvelope? envelope = HybridCipherEnvelope.FromBytes(encrypted);

        if (envelope == null)
        {
            throw new InvalidOperationException("Failed to parse Hybrid Cipher Envelope.");
        }



        byte[] asymmetricPlaintextDataEncryptionKey = Array.Empty<byte>();
        byte[] symmetricPlaintext = Array.Empty<byte>();

        try
        {
            asymmetricPlaintextDataEncryptionKey = asymmetricCipher.Decrypt(
                secretKey,
                envelope.AsymmetricEncrypted
            );

            symmetricPlaintext = symmetricCipher.Decrypt(
                asymmetricPlaintextDataEncryptionKey,
                envelope.SymmetricEncrypted
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(asymmetricPlaintextDataEncryptionKey);
        }

        return symmetricPlaintext;
    }

    public static string HybridEncryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        string publicKeyBase64,
        string plaintextUtf8
    )
    {
        byte[] publicKeyBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);

            encryptedBytes = HybridEncrypt(
                asymmetricCipher,
                symmetricCipher,
                publicKeyBytes,
                plaintextBytes
            );

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    public static string HybridDecryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        string secretKeyBase64,
        string encryptedBase64
    )
    {
        byte[] secretKeyBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        string plaintext = string.Empty;

        try
        {
            secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
            encryptedBytes = Convert.FromBase64String(encryptedBase64);

            plaintextBytes = HybridDecrypt(
                asymmetricCipher,
                symmetricCipher,
                secretKeyBytes,
                encryptedBytes
            );

            plaintext = Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKeyBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        return plaintext;
    }

    public static bool TryEncrypt(
        this IAsymmetricCipher cipher,
        byte[] publicKey,
        byte[] plaintext,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = cipher.Encrypt(publicKey, plaintext);

            return true;
        }
        catch
        {
            encrypted = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryDecrypt(
        this IAsymmetricCipher cipher,
        byte[] secretKey,
        byte[] encrypted,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = cipher.Decrypt(secretKey, encrypted);

            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryEncryptBase64(
        this IAsymmetricCipher cipher,
        string publicKeyBase64,
        string plaintextUtf8,
        out string encryptedBase64
    )
    {
        try
        {
            encryptedBase64 = cipher.EncryptBase64(publicKeyBase64, plaintextUtf8);

            return true;
        }
        catch
        {
            encryptedBase64 = string.Empty;

            return false;
        }
    }

    public static bool TryDecryptBase64(
        this IAsymmetricCipher cipher,
        string secretKeyBase64,
        string encryptedBase64,
        out string plaintextUtf8
    )
    {
        try
        {
            plaintextUtf8 = cipher.DecryptBase64(secretKeyBase64, encryptedBase64);

            return true;
        }
        catch
        {
            plaintextUtf8 = string.Empty;

            return false;
        }
    }

    public static bool TryGenerateKeyPair(
        this IAsymmetricCipher cipher,
        out byte[] publicKey,
        out byte[] secretKey
    )
    {
        try
        {
            (byte[] publicKey, byte[] secretKey) keyPair = cipher.GenerateKeyPair();
            publicKey = keyPair.publicKey;
            secretKey = keyPair.secretKey;

            return true;
        }
        catch
        {
            publicKey = Array.Empty<byte>();
            secretKey = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryGenerateKeyPairBase64(
        this IAsymmetricCipher cipher,
        out string publicKeyBase64,
        out string secretKeyBase64
    )
    {
        try
        {
            (string publicKeyBase64, string secretKeyBase64) keyPair =
                cipher.GenerateKeyPairBase64();

            publicKeyBase64 = keyPair.publicKeyBase64;
            secretKeyBase64 = keyPair.secretKeyBase64;

            return true;
        }
        catch
        {
            publicKeyBase64 = string.Empty;
            secretKeyBase64 = string.Empty;

            return false;
        }
    }

    public static bool TryHybridEncrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] publicKey,
        byte[] plaintext,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = asymmetricCipher.HybridEncrypt(symmetricCipher, publicKey, plaintext);

            return true;
        }
        catch
        {
            encrypted = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryHybridDecrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] secretKey,
        byte[] encrypted,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = asymmetricCipher.HybridDecrypt(symmetricCipher, secretKey, encrypted);

            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryHybridEncryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        string publicKeyBase64,
        string plaintextUtf8,
        out string encryptedBase64
    )
    {
        try
        {
            encryptedBase64 = asymmetricCipher.HybridEncryptBase64(
                symmetricCipher,
                publicKeyBase64,
                plaintextUtf8
            );

            return true;
        }
        catch
        {
            encryptedBase64 = string.Empty;
            return false;
        }
    }

    public static bool TryHybridDecryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        string secretKeyBase64,
        string encryptedBase64,
        out string plaintextUtf8
    )
    {
        try
        {
            plaintextUtf8 = asymmetricCipher.HybridDecryptBase64(
                symmetricCipher,
                secretKeyBase64,
                encryptedBase64
            );

            return true;
        }
        catch
        {
            plaintextUtf8 = string.Empty;
            return false;
        }
    }
}
