using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyAgreementExtensions
{
    public static string DeriveSharedSecretBase64(
        this IKeyAgreement keyAgreement,
        string secretKey,
        string peerPublicKey
    )
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] peerPublicKeyBytes = Convert.FromBase64String(peerPublicKey);

        byte[] sharedSecretBytes = keyAgreement.DeriveSharedSecret(
            secretKeyBytes,
            peerPublicKeyBytes
        );

        string sharedSecretBase64 = Convert.ToBase64String(sharedSecretBytes);

        return sharedSecretBase64;
    }

    public static (string publicKey, string secretKey) GenerateKeyPairBase64(
        this IKeyAgreement keyAgreement
    )
    {
        (byte[] publicKeyBytes, byte[] secretKeyBytes) = keyAgreement.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(secretKeyBytes);
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
        byte[] key = kdf.DeriveKey(
            inputKeyMaterial: sharedSecret,
            iterations: 1,
            cipher.KeySizeBytes,
            kdfSalt,
            kdfInfo
        );

        byte[] encrypted = cipher.Encrypt(key, plaintext);

        CryptographicOperations.ZeroMemory(key);

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
        byte[] key = kdf.DeriveKey(
            inputKeyMaterial: sharedSecret,
            iterations: 1,
            cipher.KeySizeBytes,
            kdfSalt,
            kdfInfo
        );

        byte[] decrypted = cipher.Decrypt(key, encrypted);

        CryptographicOperations.ZeroMemory(key);

        return decrypted;
    }

    public static string EncryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecret,
        string plaintext,
        string kdfSalt,
        string kdfInfo
    )
    {
        byte[] sharedSecretBytes = Convert.FromBase64String(sharedSecret);
        byte[] plaintextBytes = Convert.FromBase64String(plaintext);
        byte[] kdfSaltBytes = Convert.FromBase64String(kdfSalt);
        byte[] kdfInfoBytes = Convert.FromBase64String(kdfInfo);

        byte[] encryptedBytes = Encrypt(
            keyAgreement,
            cipher,
            kdf,
            sharedSecretBytes,
            plaintextBytes,
            kdfSaltBytes,
            kdfInfoBytes
        );

        string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

        CryptographicOperations.ZeroMemory(sharedSecretBytes);
        CryptographicOperations.ZeroMemory(plaintextBytes);
        CryptographicOperations.ZeroMemory(kdfSaltBytes);
        CryptographicOperations.ZeroMemory(kdfInfoBytes);
        CryptographicOperations.ZeroMemory(encryptedBytes);

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecret,
        string encrypted,
        string kdfSalt,
        string kdfInfo
    )
    {
        byte[] sharedSecretBytes = Convert.FromBase64String(sharedSecret);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);
        byte[] kdfSaltBytes = Convert.FromBase64String(kdfSalt);
        byte[] kdfInfoBytes = Convert.FromBase64String(kdfInfo);

        byte[] plaintextBytes = Decrypt(
            keyAgreement,
            cipher,
            kdf,
            sharedSecretBytes,
            encryptedBytes,
            kdfSaltBytes,
            kdfInfoBytes
        );

        string plaintextBase64 = Convert.ToBase64String(plaintextBytes);

        CryptographicOperations.ZeroMemory(sharedSecretBytes);
        CryptographicOperations.ZeroMemory(encryptedBytes);
        CryptographicOperations.ZeroMemory(kdfSaltBytes);
        CryptographicOperations.ZeroMemory(kdfInfoBytes);
        CryptographicOperations.ZeroMemory(plaintextBytes);

        return plaintextBase64;
    }

    public static bool TryDeriveSharedSecret(
        IKeyAgreement keyAgreement,
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
        IKeyAgreement keyAgreement,
        string secretKey,
        string peerPublicKey,
        out string derivedSharedSecret
    )
    {
        try
        {
            derivedSharedSecret = keyAgreement.DeriveSharedSecretBase64(secretKey, peerPublicKey);

            return true;
        }
        catch
        {
            derivedSharedSecret = string.Empty;

            return false;
        }
    }

    public static bool TryGenerateKeyPair(
        IKeyAgreement keyAgreement,
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
        IKeyAgreement keyAgreement,
        out string publicKey,
        out string secretKey
    )
    {
        try
        {
            (string publicKey, string secretKey) keyPair = keyAgreement.GenerateKeyPairBase64();
            publicKey = keyPair.publicKey;
            secretKey = keyPair.secretKey;

            return true;
        }
        catch
        {
            publicKey = string.Empty;
            secretKey = string.Empty;

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
            plaintext = keyAgreement.Encrypt(
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
        string sharedSecret,
        string plaintext,
        string kdfSalt,
        string kdfInfo,
        out string encrypted
    )
    {
        try
        {
            encrypted = keyAgreement.EncryptBase64(
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
            encrypted = string.Empty;

            return false;
        }
    }

    public static bool TryDecryptBase64(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        string sharedSecret,
        string encrypted,
        string kdfSalt,
        string kdfInfo,
        out string plaintext
    )
    {
        try
        {
            plaintext = keyAgreement.DecryptBase64(
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
            plaintext = string.Empty;

            return false;
        }
    }
}
