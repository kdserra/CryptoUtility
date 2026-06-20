using System.Text;

namespace CryptoUtility;

public static class AsymmetricCipherExtensions
{
    public static (bool success, string encrypted) EncryptBase64(
        this IAsymmetricCipher cipher,
        string publicKey,
        string plaintext
    )
    {
        try
        {
            if (!LibraryHelper.NotNull(cipher, publicKey, plaintext))
            {
                return (false, string.Empty);
            }

            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            (bool success, byte[] encrypted) encryptedResult = cipher.Encrypt(
                publicKeyBytes,
                plaintextBytes
            );

            if (!encryptedResult.success)
            {
                return (false, string.Empty);
            }

            string encryptedBase64 = Convert.ToBase64String(encryptedResult.encrypted);

            return (true, encryptedBase64);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    public static (bool success, string plaintext) DecryptBase64(
        this IAsymmetricCipher cipher,
        string secretKey,
        string encrypted
    )
    {
        try
        {
            if (!LibraryHelper.NotNull(cipher, secretKey, encrypted))
            {
                return (false, string.Empty);
            }

            byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);

            (bool success, byte[] plaintext) decryptedResult = cipher.Decrypt(
                secretKeyBytes,
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

    public static (string PublicKey, string SecretKey) GenerateKeyPairBase64(
        this IAsymmetricCipher cipher
    )
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return (string.Empty, string.Empty);
        }

        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = cipher.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }

    public static (bool success, byte[] encrypted) HybridEncrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] publicKey,
        byte[] plaintext
    )
    {
        try
        {
            if (
                !LibraryHelper.NotNullOrEmpty(
                    asymmetricCipher,
                    symmetricCipher,
                    publicKey,
                    plaintext
                )
            )
            {
                return (false, Array.Empty<byte>());
            }

            byte[] asymmetricPlaintextDataEncryptionKey = symmetricCipher.GenerateKey();
            (bool asymmetricSuccess, byte[] asymmetricEncrypted) = asymmetricCipher.Encrypt(
                publicKey,
                asymmetricPlaintextDataEncryptionKey
            );

            if (!asymmetricSuccess)
            {
                return (false, Array.Empty<byte>());
            }

            (bool symmetricSuccess, byte[] symmetricEncrypted) = symmetricCipher.Encrypt(
                asymmetricPlaintextDataEncryptionKey,
                plaintext
            );
            if (!symmetricSuccess)
            {
                return (false, Array.Empty<byte>());
            }

            HybridCipherEnvelope envelope = new(
                HybridCipherEnvelope.LatestVersion,
                asymmetricEncrypted,
                symmetricEncrypted
            );

            return (true, envelope.ToBytes());
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    public static (bool success, byte[] plaintext) HybridDecrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] secretKey,
        byte[] encrypted
    )
    {
        try
        {
            if (
                !LibraryHelper.NotNullOrEmpty(
                    asymmetricCipher,
                    symmetricCipher,
                    secretKey,
                    encrypted
                )
            )
            {
                return (false, Array.Empty<byte>());
            }

            HybridCipherEnvelope? envelope = HybridCipherEnvelope.FromBytes(encrypted);
            if (envelope == null)
            {
                return (false, Array.Empty<byte>());
            }

            (bool asymmetricSuccess, byte[] asymmetricPlaintextDataEncryptionKey) =
                asymmetricCipher.Decrypt(secretKey, envelope.AsymmetricEncrypted);

            if (!asymmetricSuccess || asymmetricPlaintextDataEncryptionKey.IsNullOrEmpty())
            {
                return (false, Array.Empty<byte>());
            }

            (bool symmetricSuccess, byte[] symmetricPlaintext) = symmetricCipher.Decrypt(
                asymmetricPlaintextDataEncryptionKey,
                envelope.SymmetricEncrypted
            );

            if (!symmetricSuccess || symmetricPlaintext.IsNullOrEmpty())
            {
                return (false, Array.Empty<byte>());
            }

            return (true, symmetricPlaintext);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    public static (bool success, string encrypted) HybridEncryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher cipher,
        string publicKey,
        string plaintext
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(asymmetricCipher, publicKey, plaintext))
            {
                return (false, string.Empty);
            }

            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            (bool success, byte[] encrypted) = HybridEncrypt(
                asymmetricCipher,
                cipher,
                publicKeyBytes,
                plaintextBytes
            );

            string encryptedBase64 = Convert.ToBase64String(encrypted);

            return (success, encryptedBase64);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    public static (bool success, string plaintext) HybridDecryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher cipher,
        string secretKey,
        string encrypted
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(asymmetricCipher, secretKey, encrypted))
            {
                return (false, string.Empty);
            }

            byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);

            (bool success, byte[] plaintext) result = HybridDecrypt(
                asymmetricCipher,
                cipher,
                secretKeyBytes,
                encryptedBytes
            );

            string plaintext = Encoding.UTF8.GetString(result.plaintext);
            return (result.success, plaintext);
        }
        catch
        {
            return (false, string.Empty);
        }
    }
}
