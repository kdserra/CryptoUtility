namespace CryptoUtility;

/// <summary>
/// Provides a Message Authentication Code (MAC) to verify message authenticity.
/// </summary>
public interface IMacProvider
{
    /// <summary>
    /// Gets the required or recommended key size in bytes.
    /// Values < 1 represent that there is no minimum key size requirement.
    /// </summary>
    public int RequiredKeySizeInBytes { get; }

    /// <summary>
    /// Gets the output size of the MAC in bytes.
    /// </summary>
    public int MacSizeInBytes { get; }

    /// <summary>
    /// Computes a Message Authentication Code (MAC) using the key for the message to later be verified against tampering.
    /// </summary>
    /// <param name="key">The key that will be used to compute the MAC.</param>
    /// <param name="message">The message that the MAC will be generated for.</param>
    /// <returns>The computed Message Authentication Code (MAC).</returns>
    public byte[] ComputeMac(byte[] key, byte[] message);
}
