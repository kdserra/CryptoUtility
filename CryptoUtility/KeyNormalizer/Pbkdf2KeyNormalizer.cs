using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides functionality to derive a normalized cryptographic key using the PBKDF2 algorithm.
/// </summary>
/// <remarks>
/// This implementation uses the official System.Security.Cryptography Pbkdf2 implementation which does not support .NET Standard 2.0.
/// </remarks>
public sealed class Pbkdf2KeyNormalizer : IKeyNormalizer
{
#if NET8_0_OR_GREATER
    private HashAlgorithmName _hashAlgorithm;
#endif
    private readonly byte[] _salt;
    private readonly int _iterations;

    public Pbkdf2KeyNormalizer(
#if NET8_0_OR_GREATER
        HashAlgorithmName hashAlgorithm,
#endif
        byte[] salt,
        int iterations = 100_000
    )
    {
#if NET8_0_OR_GREATER
        _hashAlgorithm = hashAlgorithm;
#endif
        _salt = salt;
        _iterations = iterations;
    }

    public byte[] Normalize(byte[] key, int keySize)
    {
#if NET8_0_OR_GREATER
        byte[] output = new byte[keySize];
        Rfc2898DeriveBytes.Pbkdf2(key, _salt, output, _iterations, _hashAlgorithm);
#else
        using Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(key, _salt, _iterations);
        byte[] output = pbkdf2.GetBytes(keySize);
#endif

        return output;
    }
}
