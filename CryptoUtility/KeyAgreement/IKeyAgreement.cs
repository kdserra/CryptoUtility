namespace CryptoUtility;

public interface IKeyAgreement
{
    public (bool success, byte[] sharedSecret) DeriveSharedSecret(
        byte[] secretKey,
        byte[] peerPublicKey
    );

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
