using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyEncapsulationMechanismExtensions
{
    /// <summary>
    /// Generates a new key pair for the KEM.
    /// </summary>
    /// <returns>A tuple containing the public key and secret (private) key.</returns>
    public static (string publicKeyBase64, string secretKeyBase64) GenerateKeyPair(
        this IKeyEncapsulationMechanism kem
    )
    {
        (byte[] publicKey, byte[] secretKey) = kem.GenerateKeyPair();

        string publicKeyBase64 = Convert.ToBase64String(publicKey);
        string secretKeyBase64 = Convert.ToBase64String(secretKey);

        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(secretKey);

        return (publicKeyBase64, secretKeyBase64);
    }

    /// <summary>
    /// Encapsulates a shared secret using the peer's public key.
    /// </summary>
    /// <param name="peerPublicKeyBase64">The peer's public key bytes.</param>
    /// <returns>A tuple containing the derived shared secret and the encapsulated ciphertext.</returns>
    public static (string sharedSecretBase64, string ciphertextBase64) EncapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string peerPublicKeyBase64
    )
    {
        byte[] peerPublicKeyBytes = Convert.FromBase64String(peerPublicKeyBase64);
        (byte[] sharedSecret, byte[] ciphertext) = kem.Encapsulate(peerPublicKeyBytes);

        string sharedSecretBase64 = Convert.ToBase64String(sharedSecret);
        string ciphertextBase64 = Convert.ToBase64String(ciphertext);

        CryptographicOperations.ZeroMemory(peerPublicKeyBytes);
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(ciphertext);

        return (sharedSecretBase64, ciphertextBase64);
    }

    /// <summary>
    /// Decapsulates the ciphertext using the secret key to recover the shared secret.
    /// </summary>
    /// <param name="secretKeyBase64">The secret (private) key bytes.</param>
    /// <param name="ciphertextBase64">The encapsulated ciphertext bytes.</param>
    /// <returns>The recovered shared secret.</returns>
    public static string DecapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string secretKeyBase64,
        string ciphertextBase64
    )
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
        byte[] ciphertextBytes = Convert.FromBase64String(ciphertextBase64);

        byte[] decapsulated = kem.Decapsulate(secretKeyBytes, ciphertextBytes);

        string decapsulatedBase64 = Convert.ToBase64String(decapsulated);

        CryptographicOperations.ZeroMemory(secretKeyBytes);
        CryptographicOperations.ZeroMemory(ciphertextBytes);
        CryptographicOperations.ZeroMemory(decapsulated);

        return decapsulatedBase64;
    }

    public static bool TryEncapsulate(
        this IKeyEncapsulationMechanism kem,
        byte[] peerPublicKey,
        out byte[] sharedSecret,
        out byte[] ciphertext
    )
    {
        try
        {
            (byte[] sharedSecret, byte[] ciphertext) result = kem.Encapsulate(peerPublicKey);

            sharedSecret = result.sharedSecret;
            ciphertext = result.ciphertext;
            return true;
        }
        catch
        {
            sharedSecret = Array.Empty<byte>();
            ciphertext = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryEncapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string peerPublicKeyBase64,
        out string sharedSecretBase64,
        out string ciphertextBase64
    )
    {
        try
        {
            (string sharedSecretBase64, string ciphertextBase64) result = kem.EncapsulateBase64(
                peerPublicKeyBase64
            );

            sharedSecretBase64 = result.sharedSecretBase64;
            ciphertextBase64 = result.ciphertextBase64;
            return true;
        }
        catch
        {
            sharedSecretBase64 = string.Empty;
            ciphertextBase64 = string.Empty;
            return false;
        }
    }

    public static bool TryDecapsulate(
        this IKeyEncapsulationMechanism kem,
        byte[] secretKey,
        byte[] ciphertext,
        out byte[] sharedSecret
    )
    {
        try
        {
            sharedSecret = kem.Decapsulate(secretKey, ciphertext);
            return true;
        }
        catch
        {
            sharedSecret = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryDecapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string secretKeyBase64,
        string ciphertextBase64,
        out string sharedSecretBase64
    )
    {
        try
        {
            sharedSecretBase64 = kem.DecapsulateBase64(secretKeyBase64, ciphertextBase64);
            return true;
        }
        catch
        {
            sharedSecretBase64 = string.Empty;
            return false;
        }
    }

    public static byte[] Encrypt(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] peerPublicKey,
        byte[] plaintext,
        byte[] kdfSalt,
        byte[] kdfInfo
    )
    {
        LibraryHelper.ThrowIfAnyNull(kem);
        LibraryHelper.ThrowIfAnyNull(cipher);
        LibraryHelper.ThrowIfAnyNull(kdf);
        if (peerPublicKey == null) throw new ArgumentNullException(nameof(peerPublicKey));
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));

        byte[] sharedSecret = Array.Empty<byte>();
        byte[] kemCiphertext = Array.Empty<byte>();
        byte[] key = Array.Empty<byte>();
        byte[] symmetricEncrypted = Array.Empty<byte>();
        byte[] envelopeBytes = Array.Empty<byte>();

        try
        {
            (sharedSecret, kemCiphertext) = kem.Encapsulate(peerPublicKey);

            key = kdf.DeriveKey(
                inputKeyMaterial: sharedSecret,
                cipher.KeySizeBytes,
                kdfSalt,
                kdfInfo
            );

            symmetricEncrypted = cipher.Encrypt(key, plaintext);

            HybridCipherEnvelope envelope = new(kemCiphertext, symmetricEncrypted);
            envelopeBytes = envelope.ToBytes();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(kemCiphertext);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(symmetricEncrypted);
        }

        return envelopeBytes;
    }

    public static byte[] Decrypt(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] secretKey,
        byte[] encrypted,
        byte[] kdfSalt,
        byte[] kdfInfo
    )
    {
        LibraryHelper.ThrowIfAnyNull(kem);
        LibraryHelper.ThrowIfAnyNull(cipher);
        LibraryHelper.ThrowIfAnyNull(kdf);
        if (secretKey == null) throw new ArgumentNullException(nameof(secretKey));
        if (encrypted == null) throw new ArgumentNullException(nameof(encrypted));

        HybridCipherEnvelope? envelope = HybridCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            throw new InvalidOperationException("Failed to parse Hybrid Cipher Envelope.");
        }

        byte[] sharedSecret = Array.Empty<byte>();
        byte[] key = Array.Empty<byte>();
        byte[] decrypted = Array.Empty<byte>();

        try
        {
            sharedSecret = kem.Decapsulate(secretKey, envelope.AsymmetricEncrypted);

            key = kdf.DeriveKey(
                inputKeyMaterial: sharedSecret,
                cipher.KeySizeBytes,
                kdfSalt,
                kdfInfo
            );

            decrypted = cipher.Decrypt(key, envelope.SymmetricEncrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(key);
        }

        return decrypted;
    }

    public static string EncryptBase64(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string peerPublicKeyBase64,
        string plaintextUtf8,
        string kdfSaltBase64,
        string kdfInfoBase64
    )
    {
        byte[] peerPublicKeyBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] kdfSaltBytes = Array.Empty<byte>();
        byte[] kdfInfoBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            peerPublicKeyBytes = Convert.FromBase64String(peerPublicKeyBase64);
            plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintextUtf8);
            kdfSaltBytes = kdfSaltBase64 != null ? Convert.FromBase64String(kdfSaltBase64) : Array.Empty<byte>();
            kdfInfoBytes = kdfInfoBase64 != null ? Convert.FromBase64String(kdfInfoBase64) : Array.Empty<byte>();

            encryptedBytes = Encrypt(
                kem,
                cipher,
                kdf,
                peerPublicKeyBytes,
                plaintextBytes,
                kdfSaltBytes,
                kdfInfoBytes
            );

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPublicKeyBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(kdfSaltBytes);
            CryptographicOperations.ZeroMemory(kdfInfoBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string secretKeyBase64,
        string encryptedBase64,
        string kdfSaltBase64,
        string kdfInfoBase64
    )
    {
        byte[] secretKeyBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] kdfSaltBytes = Array.Empty<byte>();
        byte[] kdfInfoBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        string plaintextUtf8 = string.Empty;

        try
        {
            secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
            encryptedBytes = Convert.FromBase64String(encryptedBase64);
            kdfSaltBytes = kdfSaltBase64 != null ? Convert.FromBase64String(kdfSaltBase64) : Array.Empty<byte>();
            kdfInfoBytes = kdfInfoBase64 != null ? Convert.FromBase64String(kdfInfoBase64) : Array.Empty<byte>();

            plaintextBytes = Decrypt(
                kem,
                cipher,
                kdf,
                secretKeyBytes,
                encryptedBytes,
                kdfSaltBytes,
                kdfInfoBytes
            );

            plaintextUtf8 = System.Text.Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKeyBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(kdfSaltBytes);
            CryptographicOperations.ZeroMemory(kdfInfoBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        return plaintextUtf8;
    }



    public static bool TryEncrypt(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] peerPublicKey,
        byte[] plaintext,
        byte[] kdfSalt,
        byte[] kdfInfo,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = kem.Encrypt(cipher, kdf, peerPublicKey, plaintext, kdfSalt, kdfInfo);
            return true;
        }
        catch
        {
            encrypted = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryDecrypt(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] secretKey,
        byte[] encrypted,
        byte[] kdfSalt,
        byte[] kdfInfo,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = kem.Decrypt(cipher, kdf, secretKey, encrypted, kdfSalt, kdfInfo);
            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryEncryptBase64(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string peerPublicKeyBase64,
        string plaintextUtf8,
        string kdfSaltBase64,
        string kdfInfoBase64,
        out string encryptedBase64
    )
    {
        try
        {
            encryptedBase64 = kem.EncryptBase64(cipher, kdf, peerPublicKeyBase64, plaintextUtf8, kdfSaltBase64, kdfInfoBase64);
            return true;
        }
        catch
        {
            encryptedBase64 = string.Empty;
            return false;
        }
    }

    public static bool TryDecryptBase64(
        this IKeyEncapsulationMechanism kem,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string secretKeyBase64,
        string encryptedBase64,
        string kdfSaltBase64,
        string kdfInfoBase64,
        out string plaintextUtf8
    )
    {
        try
        {
            plaintextUtf8 = kem.DecryptBase64(cipher, kdf, secretKeyBase64, encryptedBase64, kdfSaltBase64, kdfInfoBase64);
            return true;
        }
        catch
        {
            plaintextUtf8 = string.Empty;
            return false;
        }
    }

}
