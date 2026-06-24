namespace CryptoUtility;

/// <summary>
/// Defines a contract for Key Expansion Key Derivation Functions (KDFs).
/// </summary>
public interface IKeyExpansionKdf
{
    /// <summary>
    /// Derives a key of the specified length from the input key material, salt, and info context.
    /// </summary>
    /// <param name="inputKeyMaterial">The input key material (IKM).</param>
    /// <param name="outputLength">The desired length of the derived key in bytes.</param>
    /// <param name="salt">The optional salt value.</param>
    /// <param name="info">The optional context/application-specific info string bytes.</param>
    /// <returns>A byte array containing the derived key.</returns>
    public byte[] DeriveKey(byte[] inputKeyMaterial, int outputLength, byte[] salt, byte[] info);
}
