using System.Text;

namespace CryptoUtility;

public static class AsymmetricCipherExtensions
{
    public static string EncryptBase64(
        this IAsymmetricCipher cipher,
        string publicKey,
        string plaintext
    )
    {
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] encryptedBytes = cipher.Encrypt(publicKeyBytes, plaintextBytes);
        string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this IAsymmetricCipher cipher,
        string secretKey,
        string encrypted
    )
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);
        byte[] decryptedBytes = cipher.Decrypt(secretKeyBytes, encryptedBytes);
        string plaintext = Encoding.UTF8.GetString(decryptedBytes);

        return plaintext;
    }

    public static (string publicKey, string secretKey) GenerateKeyPairBase64(
        this IAsymmetricCipher cipher
    )
    {
        (byte[] publicKeyBytes, byte[] secretKeyBytes) = cipher.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(secretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }

    public static byte[] HybridEncrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] publicKey,
        byte[] plaintext
    )
    {
        byte[] asymmetricPlaintextDataEncryptionKey = symmetricCipher.GenerateKey();

        byte[] asymmetricEncrypted = asymmetricCipher.Encrypt(
            publicKey,
            asymmetricPlaintextDataEncryptionKey
        );

        byte[] symmetricEncrypted = symmetricCipher.Encrypt(
            asymmetricPlaintextDataEncryptionKey,
            plaintext
        );

        HybridCipherEnvelope envelope = new(
            HybridCipherEnvelope.LatestVersion,
            asymmetricEncrypted,
            symmetricEncrypted
        );

        return envelope.ToBytes();
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

        byte[] asymmetricPlaintextDataEncryptionKey = asymmetricCipher.Decrypt(
            secretKey,
            envelope.AsymmetricEncrypted
        );

        byte[] symmetricPlaintext = symmetricCipher.Decrypt(
            asymmetricPlaintextDataEncryptionKey,
            envelope.SymmetricEncrypted
        );

        return symmetricPlaintext;
    }

    public static string HybridEncryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        string publicKey,
        string plaintext
    )
    {
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        byte[] encryptedBytes = HybridEncrypt(
            asymmetricCipher,
            symmetricCipher,
            publicKeyBytes,
            plaintextBytes
        );

        string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

        return encryptedBase64;
    }

    public static string HybridDecryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        string secretKey,
        string encrypted
    )
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);

        byte[] plaintextBytes = HybridDecrypt(
            asymmetricCipher,
            symmetricCipher,
            secretKeyBytes,
            encryptedBytes
        );

        string plaintext = Encoding.UTF8.GetString(plaintextBytes);
        return plaintext;
    }
}
