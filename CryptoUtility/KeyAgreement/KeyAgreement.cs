namespace CryptoUtility;

internal abstract class KeyAgreement
{
    public abstract (bool success, byte[] sharedSecret) DeriveSharedSecret(
        byte[] secretKey,
        byte[] peerPublicKey
    );

    public (bool success, string sharedSecret) DeriveSharedSecretBase64(
        string secretKey,
        string peerPublicKey
    )
    {
        if (!Helper.NotNullOrEmpty(secretKey, peerPublicKey))
        {
            return (false, string.Empty);
        }

        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] peerPublicKeyBytes = Convert.FromBase64String(peerPublicKey);

        (bool success, byte[] sharedSecret) derivationResult = DeriveSharedSecret(
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

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public abstract (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public (string PublicKey, string SecretKey) GenerateKeyPairBase64()
    {
        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }
}
