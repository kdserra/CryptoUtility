namespace CryptoUtility;

/// <summary>
/// Provides a Message Authentication Code (MAC) to verify message authenticity.
/// </summary>
public interface IMacProvider
{
    /// <summary>
    /// Computes a Message Authentication Code (MAC) using the key for the message to later be verified against tampering.
    /// </summary>
    /// <param name="key">The key that will be used to compute the MAC.</param>
    /// <param name="message">The message that the MAC will be generated for.</param>
    /// <returns>The computed Message Authentication Code (MAC).</returns>
    public byte[] ComputeMac(byte[] key, byte[] message);
}
