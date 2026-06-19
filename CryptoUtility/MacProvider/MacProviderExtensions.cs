using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class MacProviderExtensions
{
    /// <summary>
    /// Calculates the recommended key size in bytes for the specified MAC provider.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <returns>The required key size if specified; otherwise, the larger value between 32 bytes and the MAC output size.</returns>
    public static int GetRecommendedKeySizeInBytes(this IMacProvider macProvider)
    {
        if (macProvider.RequiredKeySizeInBytes > 0)
        {
            return macProvider.RequiredKeySizeInBytes;
        }

        return Math.Max(32, macProvider.MacSizeInBytes);
    }

    /// <summary>
    /// Generates a cryptographically secure random key tailored to the recommended size of the MAC provider.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <returns>A byte array containing the generated key.</returns>
    public static byte[] GenerateKey(this IMacProvider macProvider)
    {
        int keySize = macProvider.GetRecommendedKeySizeInBytes();
        byte[] key = CryptoHelper.GetBytes(keySize);
        return key;
    }

    /// <summary>
    /// Generates a cryptographically secure random key and encodes it as a Base64 string.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <returns>A Base64-encoded string representing the generated key.</returns>
    public static string GenerateKeyBase64(this IMacProvider macProvider)
    {
        byte[] key = macProvider.GenerateKey();
        string keyBase64 = Convert.ToBase64String(key);
        return keyBase64;
    }

    /// <summary>
    /// Computes the Message Authentication Code (MAC) for a string message using a Base64-encoded key,
    /// returning the result as a Base64 string. Safely clears sensitive byte arrays from memory before returning.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="key">The Base64-encoded secret key.</param>
    /// <param name="message">The plain text message to authenticate.</param>
    /// <returns>The Base64-encoded MAC tag, or an empty string if validation fails.</returns>
    public static string ComputeMacBase64(this IMacProvider macProvider, string key, string message)
    {
        if (!LibraryHelper.NotNull(macProvider, key, message))
        {
            return string.Empty;
        }

        byte[] keyBytes = Convert.FromBase64String(key);
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] macBytes = macProvider.ComputeMac(keyBytes, messageBytes);
        string macBase64 = Convert.ToBase64String(macBytes);

        CryptographicOperations.ZeroMemory(keyBytes);
        CryptographicOperations.ZeroMemory(messageBytes);
        CryptographicOperations.ZeroMemory(macBytes);

        return macBase64;
    }

    /// <summary>
    /// Verifies the authenticity and integrity of a message by comparing a provided MAC tag against a computed MAC tag
    /// using a constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="key">The secret key byte array.</param>
    /// <param name="message">The message byte array.</param>
    /// <param name="mac">The expected MAC tag byte array to verify against.</param>
    /// <returns><see langword="true"/> if the MAC tag matches the computed MAC; otherwise, <see langword="false"/>.</returns>
    public static bool VerifyMac(
        this IMacProvider macProvider,
        byte[] key,
        byte[] message,
        byte[] mac
    )
    {
        if (!LibraryHelper.NotNull(macProvider, key, message, mac))
        {
            return false;
        }

        try
        {
            byte[] computedMac = macProvider.ComputeMac(key, message);
            bool result = CryptoHelper.FixedTimeEquals(computedMac, mac);

            CryptographicOperations.ZeroMemory(computedMac);
            return result;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies the authenticity and integrity of a string message using Base64-encoded inputs.
    /// Performs operations using constant-time verification.
    /// </summary>
    /// <param name="macProvider">The MAC provider instance.</param>
    /// <param name="key">The Base64-encoded secret key.</param>
    /// <param name="message">The plain text message to verify.</param>
    /// <param name="mac">The Base64-encoded expected MAC tag to verify against.</param>
    /// <returns><see langword="true"/> if the MAC tag matches the computed MAC; otherwise, <see langword="false"/>.</returns>
    public static bool VerifyBase64(
        this IMacProvider macProvider,
        string key,
        string message,
        string mac
    )
    {
        if (!LibraryHelper.NotNull(macProvider, key, message, mac))
        {
            return false;
        }

        try
        {
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] macBytes = Convert.FromBase64String(mac);
            bool isValid = macProvider.VerifyMac(keyBytes, messageBytes, macBytes);

            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(macBytes);

            return isValid;
        }
        catch
        {
            return false;
        }
    }
}
