namespace CryptoUtility;

/// <summary>
/// Defines the contract for computing cryptographic hashes.
/// </summary>
public interface IHashProvider
{
    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Hash(byte[] message);
}
