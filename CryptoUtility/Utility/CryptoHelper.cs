using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides utility methods for backwards-compatibile cryptographic operations.
/// </summary>
public static class CryptoHelper
{
    /// <summary>
    /// Backwards compatible implementation for fixed time comparisons.
    /// </summary>
    /// <param name="left"></param>
    /// <param name="right"></param>
    /// <returns>Boolean representing whether the values are equal.</returns>
    internal static bool FixedTimeEquals(byte[] left, byte[] right)
    {
#if NET8_0_OR_GREATER
        return CryptographicOperations.FixedTimeEquals(left, right);
#else
        if (left == null || right == null || left.Length != right.Length)
            return false;

        int diff = 0;

        for (int i = 0; i < left.Length; i++)
            diff |= left[i] ^ right[i];

        return diff == 0;
#endif
    }

    /// <summary>
    /// Backwards compatible implementation for fixed time comparisons to fill the specified byte array with
    /// cryptographically strong random bytes
    /// </summary>
    /// <param name="buffer">The byte array to populate with random data. This parameter must not be null.</param>
    internal static void Fill(byte[] buffer)
    {
#if NET8_0_OR_GREATER
        RandomNumberGenerator.Fill(buffer);
#else
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
#endif
    }

    /// <summary>
    /// Backwards compatible implementation to generate a byte array containing cryptographically strong random values.
    /// </summary>
    /// <param name="length">The number of random bytes to generate. Must be a positive integer.</param>
    /// <returns>A byte array of the specified length filled with random values.</returns>
    internal static byte[] GetBytes(int length)
    {
#if NET8_0_OR_GREATER
        return RandomNumberGenerator.GetBytes(length);
#else
        byte[] buffer = new byte[length];
        Fill(buffer);
        return buffer;
#endif
    }
}
