using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

/// <summary>
/// Provides extension methods for simplified key agreement and shared secret derivation.
/// </summary>
public static class KeyAgreementExtensions
{
    /// <summary>
    /// Derives a shared secret key using a private key and a peer's public key using Base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="secretKeyBase64">The Base64-encoded private (secret) key.</param>
    /// <param name="peerPublicKeyBase64">The remote peer's Base64-encoded public key.</param>
    /// <returns>A string containing the result.</returns>
    public static string DeriveSharedSecretBase64(
        this IKeyAgreement keyAgreement,
        string secretKeyBase64,
        string peerPublicKeyBase64
    )
    {
        byte[] secretKeyBytes = Array.Empty<byte>();
        byte[] peerPublicKeyBytes = Array.Empty<byte>();
        byte[] sharedSecretBytes = Array.Empty<byte>();
        string sharedSecretBase64 = string.Empty;

        try
        {
            secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
            peerPublicKeyBytes = Convert.FromBase64String(peerPublicKeyBase64);

            sharedSecretBytes = keyAgreement.DeriveSharedSecret(secretKeyBytes, peerPublicKeyBytes);

            sharedSecretBase64 = Convert.ToBase64String(sharedSecretBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKeyBytes);
            CryptographicOperations.ZeroMemory(peerPublicKeyBytes);
            CryptographicOperations.ZeroMemory(sharedSecretBytes);
        }

        return sharedSecretBase64;
    }

    /// <summary>
    /// Generates a new public/private key pair using Base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <returns>A tuple containing the resulting values.</returns>
    public static (string publicKeyBase64, string secretKeyBase64) GenerateKeyPairBase64(
        this IKeyAgreement keyAgreement
    )
    {
        byte[] publicKeyBytes = Array.Empty<byte>();
        byte[] secretKeyBytes = Array.Empty<byte>();
        string publicKeyBase64 = string.Empty;
        string secretKeyBase64 = string.Empty;

        try
        {
            (publicKeyBytes, secretKeyBytes) = keyAgreement.GenerateKeyPair();

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

    /// <summary>
    /// Encrypts the specified plaintext data.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecret">When this method returns, contains the derived shared secret bytes.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="kdfSalt">The salt value for key derivation.</param>
    /// <param name="kdfInfo">The application-specific context info for key derivation.</param>
    /// <returns>A byte array containing the result.</returns>
    public static byte[] Encrypt(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] sharedSecret,
        byte[] plaintext,
        byte[] kdfSalt,
        byte[] kdfInfo
    )
    {
        LibraryHelper.ThrowIfNull(keyAgreement);
        byte[] key = Array.Empty<byte>();
        byte[] encrypted = Array.Empty<byte>();

        try
        {
            key = kdf.DeriveKey(
                inputKeyMaterial: sharedSecret,
                cipher.KeySizeBytes,
                kdfSalt,
                kdfInfo
            );

            encrypted = cipher.Encrypt(key, plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return encrypted;
    }

    /// <summary>
    /// Decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecret">When this method returns, contains the derived shared secret bytes.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <param name="kdfSalt">The salt value for key derivation.</param>
    /// <param name="kdfInfo">The application-specific context info for key derivation.</param>
    /// <returns>A byte array containing the result.</returns>
    public static byte[] Decrypt(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] sharedSecret,
        byte[] encrypted,
        byte[] kdfSalt,
        byte[] kdfInfo
    )
    {
        LibraryHelper.ThrowIfNull(keyAgreement);
        byte[] key = Array.Empty<byte>();
        byte[] decrypted = Array.Empty<byte>();

        try
        {
            key = kdf.DeriveKey(
                inputKeyMaterial: sharedSecret,
                cipher.KeySizeBytes,
                kdfSalt,
                kdfInfo
            );

            decrypted = cipher.Decrypt(key, encrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return decrypted;
    }

    /// <summary>
    /// Encrypts the specified plaintext data using Base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecretBase64">When this method returns, contains the Base64-encoded derived shared secret.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <param name="kdfSaltBase64">The Base64-encoded salt value for key derivation.</param>
    /// <param name="kdfInfoBase64">The Base64-encoded application-specific context info for key derivation.</param>
    /// <returns>A string containing the result.</returns>
    public static string EncryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecretBase64,
        string plaintextUtf8,
        string kdfSaltBase64,
        string kdfInfoBase64
    )
    {
        byte[] sharedSecretBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] kdfSaltBytes = Array.Empty<byte>();
        byte[] kdfInfoBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            sharedSecretBytes = Convert.FromBase64String(sharedSecretBase64);
            plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
            kdfSaltBytes = Convert.FromBase64String(kdfSaltBase64);
            kdfInfoBytes = Convert.FromBase64String(kdfInfoBase64);

            encryptedBytes = Encrypt(
                keyAgreement,
                cipher,
                kdf,
                sharedSecretBytes,
                plaintextBytes,
                kdfSaltBytes,
                kdfInfoBytes
            );

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecretBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(kdfSaltBytes);
            CryptographicOperations.ZeroMemory(kdfInfoBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    /// <summary>
    /// Decrypts the specified ciphertext data using Base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecretBase64">When this method returns, contains the Base64-encoded derived shared secret.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <param name="kdfSaltBase64">The Base64-encoded salt value for key derivation.</param>
    /// <param name="kdfInfoBase64">The Base64-encoded application-specific context info for key derivation.</param>
    /// <returns>A string containing the result.</returns>
    public static string DecryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecretBase64,
        string encryptedBase64,
        string kdfSaltBase64,
        string kdfInfoBase64
    )
    {
        byte[] sharedSecretBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] kdfSaltBytes = Array.Empty<byte>();
        byte[] kdfInfoBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        string plaintextUtf8 = string.Empty;

        try
        {
            sharedSecretBytes = Convert.FromBase64String(sharedSecretBase64);
            encryptedBytes = Convert.FromBase64String(encryptedBase64);
            kdfSaltBytes = Convert.FromBase64String(kdfSaltBase64);
            kdfInfoBytes = Convert.FromBase64String(kdfInfoBase64);

            plaintextBytes = Decrypt(
                keyAgreement,
                cipher,
                kdf,
                sharedSecretBytes,
                encryptedBytes,
                kdfSaltBytes,
                kdfInfoBytes
            );

            plaintextUtf8 = Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecretBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(kdfSaltBytes);
            CryptographicOperations.ZeroMemory(kdfInfoBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        return plaintextUtf8;
    }

    /// <summary>
    /// Attempts to derives a shared secret key using a private key and a peer's public key.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <param name="peerPublicKey">The remote peer's public key.</param>
    /// <param name="derivedSharedSecret">The derived shared secret.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryDeriveSharedSecret(
        this IKeyAgreement keyAgreement,
        byte[] secretKey,
        byte[] peerPublicKey,
        out byte[] derivedSharedSecret
    )
    {
        try
        {
            derivedSharedSecret = keyAgreement.DeriveSharedSecret(secretKey, peerPublicKey);

            return true;
        }
        catch
        {
            derivedSharedSecret = Array.Empty<byte>();

            return false;
        }
    }

    /// <summary>
    /// Attempts to derives a shared secret key using a private key and a peer's public key using base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="secretKeyBase64">The Base64-encoded private (secret) key.</param>
    /// <param name="peerPublicKeyBase64">The remote peer's Base64-encoded public key.</param>
    /// <param name="derivedSharedSecretBase64">The derived shared secret base64.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryDeriveSharedSecretBase64(
        this IKeyAgreement keyAgreement,
        string secretKeyBase64,
        string peerPublicKeyBase64,
        out string derivedSharedSecretBase64
    )
    {
        try
        {
            derivedSharedSecretBase64 = keyAgreement.DeriveSharedSecretBase64(
                secretKeyBase64,
                peerPublicKeyBase64
            );

            return true;
        }
        catch
        {
            derivedSharedSecretBase64 = string.Empty;

            return false;
        }
    }

    /// <summary>
    /// Attempts to generates a new public/private key pair.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="publicKey">The public key.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryGenerateKeyPair(
        this IKeyAgreement keyAgreement,
        out byte[] publicKey,
        out byte[] secretKey
    )
    {
        try
        {
            (byte[] publicKey, byte[] secretKey) keyPair = keyAgreement.GenerateKeyPair();
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

    /// <summary>
    /// Attempts to generates a new public/private key pair using base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="publicKeyBase64">The Base64-encoded public key.</param>
    /// <param name="secretKeyBase64">The Base64-encoded private (secret) key.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryGenerateKeyPairBase64(
        this IKeyAgreement keyAgreement,
        out string publicKeyBase64,
        out string secretKeyBase64
    )
    {
        try
        {
            (string publicKeyBase64, string secretKeyBase64) keyPair =
                keyAgreement.GenerateKeyPairBase64();

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

    /// <summary>
    /// Attempts to encrypts the specified plaintext data.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecret">When this method returns, contains the derived shared secret bytes.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="kdfSalt">The salt value for key derivation.</param>
    /// <param name="kdfInfo">The application-specific context info for key derivation.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryEncrypt(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] sharedSecret,
        byte[] plaintext,
        byte[] kdfSalt,
        byte[] kdfInfo,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = keyAgreement.Encrypt(
                cipher,
                kdf,
                sharedSecret,
                plaintext,
                kdfSalt,
                kdfInfo
            );

            return true;
        }
        catch
        {
            encrypted = Array.Empty<byte>();

            return false;
        }
    }

    /// <summary>
    /// Attempts to decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecret">When this method returns, contains the derived shared secret bytes.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <param name="kdfSalt">The salt value for key derivation.</param>
    /// <param name="kdfInfo">The application-specific context info for key derivation.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryDecrypt(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] sharedSecret,
        byte[] encrypted,
        byte[] kdfSalt,
        byte[] kdfInfo,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = keyAgreement.Decrypt(
                cipher,
                kdf,
                sharedSecret,
                encrypted,
                kdfSalt,
                kdfInfo
            );

            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();

            return false;
        }
    }

    /// <summary>
    /// Attempts to encrypts the specified plaintext data using base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecretBase64">When this method returns, contains the Base64-encoded derived shared secret.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <param name="kdfSaltBase64">The Base64-encoded salt value for key derivation.</param>
    /// <param name="kdfInfoBase64">The Base64-encoded application-specific context info for key derivation.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryEncryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecretBase64,
        string plaintextUtf8,
        string kdfSaltBase64,
        string kdfInfoBase64,
        out string encryptedBase64
    )
    {
        try
        {
            encryptedBase64 = keyAgreement.EncryptBase64(
                cipher,
                kdf,
                sharedSecretBase64,
                plaintextUtf8,
                kdfSaltBase64,
                kdfInfoBase64
            );

            return true;
        }
        catch
        {
            encryptedBase64 = string.Empty;

            return false;
        }
    }

    /// <summary>
    /// Attempts to decrypts the specified ciphertext data using base64-encoded strings.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="kdf">The key derivation function instance.</param>
    /// <param name="sharedSecretBase64">When this method returns, contains the Base64-encoded derived shared secret.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <param name="kdfSaltBase64">The Base64-encoded salt value for key derivation.</param>
    /// <param name="kdfInfoBase64">The Base64-encoded application-specific context info for key derivation.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryDecryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecretBase64,
        string encryptedBase64,
        string kdfSaltBase64,
        string kdfInfoBase64,
        out string plaintextUtf8
    )
    {
        try
        {
            plaintextUtf8 = keyAgreement.DecryptBase64(
                cipher,
                kdf,
                sharedSecretBase64,
                encryptedBase64,
                kdfSaltBase64,
                kdfInfoBase64
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
