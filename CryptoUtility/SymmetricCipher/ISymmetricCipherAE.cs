namespace CryptoUtility;

/// <summary>
/// Defines the contract for authenticated symmetric key encryption and decryption (AEAD).
/// </summary>
public interface ISymmetricCipherAE : ISymmetricCipher
{
    /// <summary>
    /// Gets the auth tag size bytes.
    /// </summary>
    public int AuthTagSizeBytes { get; }
}
