using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides utility methods.
/// </summary>
internal static class Helper
{
    public static SymmetricCipher? GetSymmetricCipherFromID(SymmetricCipherID cipherID)
    {
        switch (cipherID)
        {
            case SymmetricCipherID.None:
            default:
                return null;
        }
    }

    public static AsymmetricCipher? GetAsymmetricCipherFromID(AsymmetricCipherID cipherID)
    {
        switch (cipherID)
        {
            case AsymmetricCipherID.None:
            default:
                return null;
        }
    }

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

    internal static bool NotNull(params object?[] objects)
    {
        foreach (object? obj in objects)
        {
            if (obj == null)
            {
                return false;
            }
        }

        return true;
    }

    internal static bool NotNullOrEmpty(params object?[] objects)
    {
        foreach (var obj in objects)
        {
            if (obj == null)
                return false;

            if (obj is string str && string.IsNullOrEmpty(str))
                return false;

            if (
                obj is System.Collections.IEnumerable enumerable
                && !enumerable.Cast<object>().Any()
            )
                return false;
        }

        return true;
    }

    internal static void ThrowIfAnyNull(params object?[] objects)
    {
        foreach (object? obj in objects)
        {
            if (obj == null)
            {
                throw new InvalidOperationException();
            }
        }
    }

    internal static bool IsNullOrEmpty<T>(this ICollection<T> collection)
    {
        return collection == null || collection.Count == 0;
    }
}
