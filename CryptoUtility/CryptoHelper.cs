using System.Security.Cryptography;

namespace CryptoUtility;

public static class CryptoHelper
{
    public static readonly IKeyNormalizer DefaultKeyNormalizer = new Pbkdf2KeyNormalizer(
#if NET8_0_OR_GREATER
        hashAlgorithm: HashAlgorithmName.SHA256,
#endif
        salt: []
    );

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

    public static void Fill(byte[] buffer)
    {
#if NET8_0_OR_GREATER
        RandomNumberGenerator.Fill(buffer);
#else
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
#endif
    }

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
