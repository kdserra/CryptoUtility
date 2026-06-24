using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Defines a contract for Message Authentication Code (MAC) providers.
/// </summary>
public interface IMacProvider
{
    /// <summary>
    /// Gets the required key size in bytes.
    /// </summary>
    public int RequiredKeySizeInBytes { get; }

    /// <summary>
    /// Gets the size of the MAC tag in bytes.
    /// </summary>
    public int MacSizeInBytes { get; }

    /// <summary>
    /// Computes the MAC tag for the specified message using the key.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="message">The message to authenticate.</param>
    /// <returns>A byte array containing the MAC tag.</returns>
    public byte[] ComputeMac(byte[] key, byte[] message);

    /// <summary>
    /// Verifies the MAC tag for the specified message using the key.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="mac">The MAC tag to verify.</param>
    /// <returns><c>true</c> if the MAC tag is valid; otherwise, <c>false</c>.</returns>
    public bool VerifyMac(byte[] key, byte[] message, byte[] mac)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(mac);
        byte[] computedMac = ComputeMac(key, message);
        try
        {
            return CryptographicOperations.FixedTimeEquals(computedMac, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedMac);
        }
    }
}
