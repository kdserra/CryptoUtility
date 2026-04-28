namespace CryptoUtility;

/// <summary>
/// Digital signature algorithms support signing and verifying messages using secret and public keys.
/// </summary>
public interface IDigitalSignature
{
    /// <summary>
    /// Signs the specified message using the provided secret key and returns a value indicating whether the operation
    /// was successful along with the generated signature.
    /// </summary>
    /// <param name="message">The message to sign, represented as a byte array. This parameter must not be null or empty.</param>
    /// <param name="secretKey">The secret key used to sign the message, represented as a byte array. This parameter must not be null or empty.</param>
    /// <returns>A tuple containing a boolean that indicates whether the signing operation succeeded, and a byte array containing
    /// the generated signature. If the operation fails, the signature array will be empty.</returns>
    public (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey);

    /// <summary>
    /// Verifies the authenticity of a message using the specified digital signature and public key.
    /// </summary>
    /// <param name="message">The byte array containing the message whose signature is to be verified.</param>
    /// <param name="signature">The byte array that holds the digital signature to validate against the message.</param>
    /// <param name="publicKey">The byte array representing the public key to use for signature verification.</param>
    /// <returns>true if the signature is valid for the given message and public key; otherwise, false.</returns>
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    /// <summary>
    /// Generates a new cryptographic key for use in signature and verification operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();
}
