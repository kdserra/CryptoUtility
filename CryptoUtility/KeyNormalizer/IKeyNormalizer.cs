namespace CryptoUtility;

/// <summary>
/// Defines a contract for normalizing cryptographic keys to a specified size.
/// </summary>
public interface IKeyNormalizer
{
    /// <summary>
    /// Normalizes the specified key to ensure it meets the required size for cryptographic operations.
    /// </summary>
    byte[] Normalize(byte[] key, int keySize);
}
