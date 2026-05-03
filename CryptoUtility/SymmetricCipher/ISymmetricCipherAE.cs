namespace CryptoUtility;

/// <summary>
/// Symmetric Authenticated Encryption Ciphers additionally compute a tag upon encryption, that is verified upon
/// decryption.
/// </summary>
public interface ISymmetricCipherAE : ISymmetricCipher
{
    /// <summary>
    /// Gets the size, in bytes, of the authentication tag. This tag is used to verify that the encrypted data (and any
    /// additional data) has not been changed or tampered with.
    /// </summary>
    public int AuthTagSizeBytes { get; }
}
