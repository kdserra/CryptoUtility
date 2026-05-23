using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyAgreementExtensions
{
    /// <summary>
    /// Derives a shared secret in Base64 using the specified secret key and peer public key.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="secretKey">The secret key in Base64 format.</param>
    /// <param name="peerPublicKey">The peer's public key in Base64 format.</param>
    /// <returns>A tuple indicating success and the derived shared secret in Base64 format.</returns>
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

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
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

    /// <summary>
    /// Encrypts plaintext using a key derived from a shared secret via key agreement.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="sharedSecret">The derived shared secret bytes.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="kdfInfo">Context/application specific information bytes for KDF derivation.</param>
    /// <param name="cipher">The symmetric cipher to use. If null, defaults to AES-256 GCM.</param>
    /// <param name="kdf">The key derivation function to use. If null, defaults to HKDF.</param>
    /// <returns>A tuple indicating success and the encrypted bytes.</returns>
    public static (bool success, byte[] encrypted) Encrypt(
        this IKeyAgreement keyAgreement,
        byte[] sharedSecret,
        byte[] plaintext,
        byte[] kdfSalt,
        byte[] kdfInfo,
        ISymmetricCipher? cipher = null,
        IKeyExpansionKdf? kdf = null
    )
    {
        cipher ??= Aes256GcmImpl.Shared;
        kdf ??= HkdfStandardImpl.Shared;

        if (!LibraryHelper.NotNull(keyAgreement, sharedSecret, plaintext, kdfSalt, kdfInfo))
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

    /// <summary>
    /// Decrypts ciphertext using a key derived from a shared secret via key agreement.
    /// </summary>
    /// <param name="keyAgreement">The key agreement instance.</param>
    /// <param name="sharedSecret">The derived shared secret bytes.</param>
    /// <param name="encrypted">The encrypted bytes to decrypt.</param>
    /// <param name="kdfInfo">Context/application specific information bytes for KDF derivation.</param>
    /// <param name="cipher">The symmetric cipher to use. If null, defaults to AES-256 GCM.</param>
    /// <param name="kdf">The key derivation function to use. If null, defaults to HKDF.</param>
    /// <returns>A tuple indicating success and the decrypted bytes.</returns>
    public static (bool success, byte[] decrypted) Decrypt(
        this IKeyAgreement keyAgreement,
        byte[] sharedSecret,
        byte[] encrypted,
        byte[] kdfSalt,
        byte[] kdfInfo,
        ISymmetricCipher? cipher = null,
        IKeyExpansionKdf? kdf = null
    )
    {
        cipher ??= Aes256GcmImpl.Shared;
        kdf ??= HkdfStandardImpl.Shared;

        if (!LibraryHelper.NotNull(keyAgreement, sharedSecret, encrypted, kdfSalt, kdfInfo))
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
