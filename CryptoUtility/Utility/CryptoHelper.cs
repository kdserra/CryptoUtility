using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides general cryptographic helper utilities with a backwards-compatible implementation for older .NET runtimes.
/// </summary>
public static class CryptoHelper
{
    /// <summary>
    /// Determines whether two byte arrays are equal in value using a constant-time comparison algorithm.
    /// This method helps mitigate timing side-channel attacks by ensuring the execution time does not depend on the data values.
    /// </summary>
    /// <param name="left">The first byte array to compare.</param>
    /// <param name="right">The second byte array to compare.</param>
    /// <returns><c>true</c> if both byte arrays have the same length and identical values; otherwise, <c>false</c>.</returns>
    public static bool FixedTimeEquals(byte[] left, byte[] right)
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
    /// Fills the specified buffer with cryptographically strong, random bytes.
    /// </summary>
    /// <param name="buffer">The byte array to be filled with secure random data.</param>
    public static void Fill(byte[] buffer)
    {
#if NET8_0_OR_GREATER
        RandomNumberGenerator.Fill(buffer);
#else
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
#endif
    }

    /// <summary>
    /// Generates a byte array of the specified length filled with cryptographically strong, random bytes.
    /// </summary>
    /// <param name="length">The number of secure random bytes to generate.</param>
    /// <returns>A new byte array containing the generated secure random data.</returns>
    public static byte[] GetBytes(int length)
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
