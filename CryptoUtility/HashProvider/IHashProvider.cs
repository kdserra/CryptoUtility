namespace CryptoUtility;

/// <summary>
/// Provides an abstract base class for hashing related operations, allowing derived classes to implement specific
/// hashing algorithms.
/// </summary>
public interface IHashProvider
{
    /// <summary>
    /// Computes the hash value for the specified input data using the algorithm implemented by the derived class.
    /// </summary>
    /// <param name="message">The byte array containing the data to hash. This parameter must not be null or empty.</param>
    /// <returns>A byte array that contains the computed hash value.</returns>
    public byte[] Hash(byte[] message);
}
