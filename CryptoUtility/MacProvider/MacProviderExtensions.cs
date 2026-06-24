using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

/// <summary>
/// Provides extension methods for simplified Message Authentication Code (MAC) computation and verification.
/// </summary>
public static class MacProviderExtensions
{
    /// <summary>
    /// Get recommended key size in bytes.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <returns>The size in bytes.</returns>
    public static int GetRecommendedKeySizeInBytes(this IMacProvider macProvider)
    {
        if (macProvider.RequiredKeySizeInBytes > 0)
        {
            return macProvider.RequiredKeySizeInBytes;
        }

        return Math.Max(32, macProvider.MacSizeInBytes);
    }

    /// <summary>
    /// Generate key.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <returns>A byte array containing the result.</returns>
    public static byte[] GenerateKey(this IMacProvider macProvider)
    {
        int keySize = macProvider.GetRecommendedKeySizeInBytes();
        byte[] key = CryptoHelper.GetBytes(keySize);

        return key;
    }

    /// <summary>
    /// Generate key using Base64-encoded strings.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <returns>A string containing the result.</returns>
    public static string GenerateKeyBase64(this IMacProvider macProvider)
    {
        byte[] keyBytes = Array.Empty<byte>();
        string keyBase64 = string.Empty;

        try
        {
            keyBytes = macProvider.GenerateKey();

            keyBase64 = Convert.ToBase64String(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return keyBase64;
    }

    /// <summary>
    /// Computes the Message Authentication Code (MAC) for the specified message using the provided key using Base64-encoded strings.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <returns>A string containing the result.</returns>
    public static string ComputeMacBase64(
        this IMacProvider macProvider,
        string keyBase64,
        string messageUtf8
    )
    {
        byte[] keyBytes = Array.Empty<byte>();
        byte[] messageBytes = Array.Empty<byte>();
        byte[] macBytes = Array.Empty<byte>();
        string macBase64 = string.Empty;

        try
        {
            keyBytes = Convert.FromBase64String(keyBase64);
            messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
            macBytes = macProvider.ComputeMac(keyBytes, messageBytes);

            macBase64 = Convert.ToBase64String(macBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(macBytes);
        }

        return macBase64;
    }

    /// <summary>
    /// Verifies the Message Authentication Code (MAC) for the specified message.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="message">The input data to process.</param>
    /// <param name="mac">The Message Authentication Code (MAC) bytes.</param>
    /// <returns>true if the verification succeeded; otherwise, false.</returns>
    public static bool VerifyMac(
        this IMacProvider macProvider,
        byte[] key,
        byte[] message,
        byte[] mac
    )
    {
        LibraryHelper.ThrowIfAnyNull(key, message, mac);

        byte[] computedMac = Array.Empty<byte>();
        bool isValid = false;

        try
        {
            computedMac = macProvider.ComputeMac(key, message);

            isValid = CryptoHelper.FixedTimeEquals(computedMac, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedMac);
        }

        return isValid;
    }

    /// <summary>
    /// Verifies the digital signature of the specified input data using Base64-encoded strings.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <param name="macBase64">The Base64-encoded Message Authentication Code (MAC).</param>
    /// <returns>true if the verification succeeded; otherwise, false.</returns>
    public static bool VerifyBase64(
        this IMacProvider macProvider,
        string keyBase64,
        string messageUtf8,
        string macBase64
    )
    {
        byte[] keyBytes = Array.Empty<byte>();
        byte[] messageBytes = Array.Empty<byte>();
        byte[] macBytes = Array.Empty<byte>();
        bool isValid = false;

        try
        {
            keyBytes = Convert.FromBase64String(keyBase64);
            messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
            macBytes = Convert.FromBase64String(macBase64);

            isValid = macProvider.VerifyMac(keyBytes, messageBytes, macBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(macBytes);
        }

        return isValid;
    }

    /// <summary>
    /// Attempts to computes the message authentication code (mac) for the specified message using the provided key.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="message">The input data to process.</param>
    /// <param name="mac">The Message Authentication Code (MAC) bytes.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryComputeMac(
        this IMacProvider macProvider,
        byte[] key,
        byte[] message,
        out byte[] mac
    )
    {
        try
        {
            mac = macProvider.ComputeMac(key, message);

            return true;
        }
        catch
        {
            mac = Array.Empty<byte>();

            return false;
        }
    }

    /// <summary>
    /// Attempts to computes the message authentication code (mac) for the specified message using the provided key using base64-encoded strings.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <param name="macBase64">The Base64-encoded Message Authentication Code (MAC).</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>
    public static bool TryComputeMacBase64(
        this IMacProvider macProvider,
        string keyBase64,
        string messageUtf8,
        out string macBase64
    )
    {
        try
        {
            macBase64 = macProvider.ComputeMacBase64(keyBase64, messageUtf8);

            return true;
        }
        catch
        {
            macBase64 = string.Empty;

            return false;
        }
    }
}
