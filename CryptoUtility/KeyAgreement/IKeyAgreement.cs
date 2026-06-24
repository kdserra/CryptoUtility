namespace CryptoUtility;

/// <summary>
/// Defines the contract for cryptographic key agreement (Diffie-Hellman).
/// </summary>
public interface IKeyAgreement
{
    /// <summary>
    /// Derives a shared secret key using a private key and a peer's public key.
    /// </summary>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <param name="peerPublicKey">The remote peer's public key.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] DeriveSharedSecret(byte[] secretKey, byte[] peerPublicKey);

    /// <summary>
    /// Generates a new public/private key pair.
    /// </summary>
    /// <returns>A tuple containing the resulting values.</returns>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair();
}
