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

    public static byte[] HybridEncrypt(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        byte[] peerKemPublicKey,
        byte[] peerAsymmetricPublicKey,
        byte[] plaintext,
        byte[] kdfInfo
    )
    {
        LibraryHelper.ThrowIfAnyNull(kem);
        LibraryHelper.ThrowIfAnyNull(asymmetricCipher);
        LibraryHelper.ThrowIfAnyNull(symmetricCipher);
        LibraryHelper.ThrowIfAnyNull(kdf);
        if (peerKemPublicKey == null) throw new ArgumentNullException(nameof(peerKemPublicKey));
        if (peerAsymmetricPublicKey == null) throw new ArgumentNullException(nameof(peerAsymmetricPublicKey));
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));

        byte[] kemSecret = Array.Empty<byte>();
        byte[] kemCiphertext = Array.Empty<byte>();
        byte[] symKey = Array.Empty<byte>();
        byte[] encryptedSymKey = Array.Empty<byte>();
        byte[] hybridKey = Array.Empty<byte>();
        byte[] symmetricEncrypted = Array.Empty<byte>();
        byte[] envelopeBytes = Array.Empty<byte>();

        try
        {
            (kemSecret, kemCiphertext) = kem.Encapsulate(peerKemPublicKey);

            symKey = symmetricCipher.GenerateKey();

            encryptedSymKey = asymmetricCipher.Encrypt(peerAsymmetricPublicKey, symKey);

            hybridKey = kdf.DeriveKey(
                kemSecret,
                symmetricCipher.KeySizeBytes,
                salt: encryptedSymKey,
                info: kdfInfo
            );

            symmetricEncrypted = symmetricCipher.Encrypt(hybridKey, plaintext);

            HybridPostQuantumCipherEnvelope envelope = new(kemCiphertext, encryptedSymKey, symmetricEncrypted);
            envelopeBytes = envelope.ToBytes();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kemSecret);
            CryptographicOperations.ZeroMemory(kemCiphertext);
            CryptographicOperations.ZeroMemory(symKey);
            CryptographicOperations.ZeroMemory(encryptedSymKey);
            CryptographicOperations.ZeroMemory(hybridKey);
            CryptographicOperations.ZeroMemory(symmetricEncrypted);
        }

        return envelopeBytes;
    }

    public static byte[] HybridDecrypt(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        byte[] secretKemKey,
        byte[] secretAsymmetricKey,
        byte[] encrypted,
        byte[] kdfInfo
    )
    {
        LibraryHelper.ThrowIfAnyNull(kem);
        LibraryHelper.ThrowIfAnyNull(asymmetricCipher);
        LibraryHelper.ThrowIfAnyNull(symmetricCipher);
        LibraryHelper.ThrowIfAnyNull(kdf);
        if (secretKemKey == null) throw new ArgumentNullException(nameof(secretKemKey));
        if (secretAsymmetricKey == null) throw new ArgumentNullException(nameof(secretAsymmetricKey));
        if (encrypted == null) throw new ArgumentNullException(nameof(encrypted));

        HybridPostQuantumCipherEnvelope? envelope = HybridPostQuantumCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            throw new InvalidOperationException("Failed to parse Hybrid Post-Quantum Cipher Envelope.");
        }

        byte[] decryptedKemSecret = Array.Empty<byte>();
        byte[] decryptedSymKey = Array.Empty<byte>();
        byte[] hybridKey = Array.Empty<byte>();
        byte[] decrypted = Array.Empty<byte>();

        try
        {
            decryptedKemSecret = kem.Decapsulate(secretKemKey, envelope.KemCiphertext);

            decryptedSymKey = asymmetricCipher.Decrypt(secretAsymmetricKey, envelope.AsymmetricEncrypted);

            hybridKey = kdf.DeriveKey(
                decryptedKemSecret,
                symmetricCipher.KeySizeBytes,
                salt: envelope.AsymmetricEncrypted,
                info: kdfInfo
            );

            decrypted = symmetricCipher.Decrypt(hybridKey, envelope.SymmetricEncrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decryptedKemSecret);
            CryptographicOperations.ZeroMemory(decryptedSymKey);
            CryptographicOperations.ZeroMemory(hybridKey);
        }

        return decrypted;
    }

    public static string HybridEncryptBase64(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        string peerKemPublicKeyBase64,
        string peerAsymmetricPublicKeyBase64,
        string plaintextUtf8,
        string kdfInfoBase64
    )
    {
        byte[] peerKemPublicKeyBytes = Array.Empty<byte>();
        byte[] peerAsymmetricPublicKeyBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] kdfInfoBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            peerKemPublicKeyBytes = Convert.FromBase64String(peerKemPublicKeyBase64);
            peerAsymmetricPublicKeyBytes = Convert.FromBase64String(peerAsymmetricPublicKeyBase64);
            plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintextUtf8);
            kdfInfoBytes = kdfInfoBase64 != null ? Convert.FromBase64String(kdfInfoBase64) : Array.Empty<byte>();

            encryptedBytes = HybridEncrypt(
                kem,
                asymmetricCipher,
                symmetricCipher,
                kdf,
                peerKemPublicKeyBytes,
                peerAsymmetricPublicKeyBytes,
                plaintextBytes,
                kdfInfoBytes
            );

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerKemPublicKeyBytes);
            CryptographicOperations.ZeroMemory(peerAsymmetricPublicKeyBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(kdfInfoBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    public static string HybridDecryptBase64(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        string secretKemKeyBase64,
        string secretAsymmetricKeyBase64,
        string encryptedBase64,
        string kdfInfoBase64
    )
    {
        byte[] secretKemKeyBytes = Array.Empty<byte>();
        byte[] secretAsymmetricKeyBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] kdfInfoBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        string plaintextUtf8 = string.Empty;

        try
        {
            secretKemKeyBytes = Convert.FromBase64String(secretKemKeyBase64);
            secretAsymmetricKeyBytes = Convert.FromBase64String(secretAsymmetricKeyBase64);
            encryptedBytes = Convert.FromBase64String(encryptedBase64);
            kdfInfoBytes = kdfInfoBase64 != null ? Convert.FromBase64String(kdfInfoBase64) : Array.Empty<byte>();

            plaintextBytes = HybridDecrypt(
                kem,
                asymmetricCipher,
                symmetricCipher,
                kdf,
                secretKemKeyBytes,
                secretAsymmetricKeyBytes,
                encryptedBytes,
                kdfInfoBytes
            );

            plaintextUtf8 = System.Text.Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKemKeyBytes);
            CryptographicOperations.ZeroMemory(secretAsymmetricKeyBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
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

    public static bool TryHybridEncrypt(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        byte[] peerKemPublicKey,
        byte[] peerAsymmetricPublicKey,
        byte[] plaintext,
        byte[] kdfInfo,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = kem.HybridEncrypt(asymmetricCipher, symmetricCipher, kdf, peerKemPublicKey, peerAsymmetricPublicKey, plaintext, kdfInfo);
            return true;
        }
        catch
        {
            encrypted = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryHybridDecrypt(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        byte[] secretKemKey,
        byte[] secretAsymmetricKey,
        byte[] encrypted,
        byte[] kdfInfo,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = kem.HybridDecrypt(asymmetricCipher, symmetricCipher, kdf, secretKemKey, secretAsymmetricKey, encrypted, kdfInfo);
            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryHybridEncryptBase64(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        string peerKemPublicKeyBase64,
        string peerAsymmetricPublicKeyBase64,
        string plaintextUtf8,
        string kdfInfoBase64,
        out string encryptedBase64
    )
    {
        try
        {
            encryptedBase64 = kem.HybridEncryptBase64(asymmetricCipher, symmetricCipher, kdf, peerKemPublicKeyBase64, peerAsymmetricPublicKeyBase64, plaintextUtf8, kdfInfoBase64);
            return true;
        }
        catch
        {
            encryptedBase64 = string.Empty;
            return false;
        }
    }

    public static bool TryHybridDecryptBase64(
        this IKeyEncapsulationMechanism kem,
        IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        IKeyExpansionKdf kdf,
        string secretKemKeyBase64,
        string secretAsymmetricKeyBase64,
        string encryptedBase64,
        string kdfInfoBase64,
        out string plaintextUtf8
    )
    {
        try
        {
            plaintextUtf8 = kem.HybridDecryptBase64(asymmetricCipher, symmetricCipher, kdf, secretKemKeyBase64, secretAsymmetricKeyBase64, encryptedBase64, kdfInfoBase64);
            return true;
        }
        catch
        {
            plaintextUtf8 = string.Empty;
            return false;
        }
    }
}
