namespace CryptoUtility;

/// <summary>
/// Defines the contract for computing and verifying digital signatures.
/// </summary>
public interface IDigitalSignature
{
    /// <summary>
    /// Computes the digital signature for the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Sign(byte[] message, byte[] secretKey);

    /// <summary>
    /// Verifies the digital signature of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <param name="signature">The digital signature to verify.</param>
    /// <param name="publicKey">The public key.</param>
    /// <returns>true if the verification succeeded; otherwise, false.</returns>
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    /// <summary>
    /// Generates a new public/private key pair.
    /// </summary>
    /// <returns>A tuple containing the resulting values.</returns>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair();
}
