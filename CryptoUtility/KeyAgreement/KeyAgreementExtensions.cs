using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyAgreementExtensions
{
    public static (bool success, string sharedSecret) DeriveSharedSecretBase64(
        this IKeyAgreement keyAgreement,
        string secretKey,
        string peerPublicKey
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(keyAgreement, secretKey, peerPublicKey))
            {
                return (false, string.Empty);
            }

            byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
            byte[] peerPublicKeyBytes = Convert.FromBase64String(peerPublicKey);

            (bool success, byte[] sharedSecret) derivationResult = keyAgreement.DeriveSharedSecret(
                secretKeyBytes,
                peerPublicKeyBytes
            );

            if (!derivationResult.success)
            {
                return (false, string.Empty);
            }

            string derivedSharedSecret = Convert.ToBase64String(derivationResult.sharedSecret);

            return (true, derivedSharedSecret);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    public static (string PublicKey, string SecretKey) GenerateKeyPairBase64(
        this IKeyAgreement keyAgreement
    )
    {
        if (!LibraryHelper.NotNull(keyAgreement))
        {
            return (string.Empty, string.Empty);
        }

        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = keyAgreement.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }

    public static (bool success, byte[] encrypted) Encrypt(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] sharedSecret,
        byte[] plaintext,
        byte[] kdfSalt,
        byte[] kdfInfo
    )
    {
        if (
            !LibraryHelper.NotNull(
                keyAgreement,
                cipher,
                kdf,
                sharedSecret,
                plaintext,
                kdfSalt,
                kdfInfo
            )
        )
        {
            return (false, Array.Empty<byte>());
        }

        byte[] key = kdf.DeriveKey(
            inputKeyMaterial: sharedSecret,
            iterations: 1,
            cipher.KeySizeBytes,
            kdfSalt,
            kdfInfo
        );

        (bool success, byte[] encrypted) = cipher.Encrypt(key, plaintext);

        CryptographicOperations.ZeroMemory(key);

        return (success, encrypted);
    }

    public static (bool success, byte[] decrypted) Decrypt(
        this IKeyAgreement keyAgreement,
        ISymmetricCipher cipher,
        IKeyExpansionKdf kdf,
        byte[] sharedSecret,
        byte[] encrypted,
        byte[] kdfSalt,
        byte[] kdfInfo
    )
    {
        if (
            !LibraryHelper.NotNull(
                keyAgreement,
                cipher,
                kdf,
                sharedSecret,
                encrypted,
                kdfSalt,
                kdfInfo
            )
        )
        {
            return (false, Array.Empty<byte>());
        }

        byte[] key = kdf.DeriveKey(
            inputKeyMaterial: sharedSecret,
            iterations: 1,
            cipher.KeySizeBytes,
            kdfSalt,
            kdfInfo
        );

        (bool success, byte[] decrypted) = cipher.Decrypt(key, encrypted);

        CryptographicOperations.ZeroMemory(key);

        return (success, decrypted);
    }
}
