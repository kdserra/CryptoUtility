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
}
