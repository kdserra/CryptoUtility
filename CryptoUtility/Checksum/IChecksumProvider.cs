namespace CryptoUtility;

/// <summary>
/// Defines a contract for non-cryptographic, non-security hashing (checksum) algorithms.
/// </summary>
public interface IChecksumProvider
{
    /// <summary>
    /// Gets the size of the checksum in bytes.
    /// </summary>
    public int ChecksumSizeInBytes { get; }

    /// <summary>
    /// Computes the checksum of the specified input data.
    /// </summary>
    /// <param name="data">The byte array to compute the checksum for.</param>
    /// <returns>A byte array containing the checksum.</returns>
    public byte[] ComputeChecksum(byte[] data);
}
