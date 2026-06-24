using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class KeyAgreementExtensions
{
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

            sharedSecretBytes = keyAgreement.DeriveSharedSecret(
                secretKeyBytes,
                peerPublicKeyBytes
            );

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
        LibraryHelper.ThrowIfAnyNull(keyAgreement);
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
        LibraryHelper.ThrowIfAnyNull(keyAgreement);
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
