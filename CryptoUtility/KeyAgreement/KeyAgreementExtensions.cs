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
            if (!LibraryHelper.NotNullOrEmpty(secretKey, peerPublicKey))
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

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public static (string PublicKey, string SecretKey) GenerateKeyPairBase64(
        this IKeyAgreement keyAgreement
    )
    {
        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = keyAgreement.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }

    public static (bool success, byte[] encrypted) Encrypt(
        this IKeyAgreement keyAgreement,
        byte[] sharedSecret,
        byte[] plaintext,
        SymmetricCipherID cipherID = SymmetricCipherID.Aes256GcmSystem,
        KeyExpansionKdfID kdfID = KeyExpansionKdfID.HkdfSystem
    )
    {
        SymmetricCipher? cipher = LibraryHelper.GetSymmetricCipherFromID(cipherID);
        if (cipher == null)
        {
            return (false, []);
        }

        IKeyExpansionKdf? kdf = LibraryHelper.GetKeyExpansionKdfFromID(kdfID);
        if (kdf == null)
        {
            return (false, []);
        }

        byte[] sharedSalt = cipher.GenerateNonce();

        byte[] key = kdf.DeriveKey(
            inputKeyMaterial: sharedSecret,
            salt: sharedSalt,
            iterations: 1,
            cipher.KeySizeBytes
        );

        (bool success, byte[] encrypted) = cipher.Encrypt(key, plaintext);

        CryptographicOperations.ZeroMemory(sharedSalt);
        CryptographicOperations.ZeroMemory(key);

        return (success, encrypted);
    }

    public static (bool success, byte[] encrypted) Decrypt(
        this IKeyAgreement keyAgreement,
        byte[] sharedSecret,
        byte[] plaintext,
        SymmetricCipherID cipherID = SymmetricCipherID.Aes256GcmSystem,
        KeyExpansionKdfID kdfID = KeyExpansionKdfID.HkdfSystem
    )
    {
        SymmetricCipher? cipher = LibraryHelper.GetSymmetricCipherFromID(cipherID);
        if (cipher == null)
        {
            return (false, []);
        }

        IKeyExpansionKdf? kdf = LibraryHelper.GetKeyExpansionKdfFromID(kdfID);
        if (kdf == null)
        {
            return (false, []);
        }

        byte[] sharedSalt = cipher.GenerateNonce();

        byte[] key = kdf.DeriveKey(
            inputKeyMaterial: sharedSecret,
            salt: sharedSalt,
            iterations: 1,
            cipher.KeySizeBytes
        );

        (bool success, byte[] decrypted) = cipher.Decrypt(key, plaintext);

        CryptographicOperations.ZeroMemory(sharedSalt);
        CryptographicOperations.ZeroMemory(key);

        return (success, decrypted);
    }
}
