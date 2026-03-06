#if NET8_0_OR_GREATER
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
    private HashAlgorithmName _hashAlgorithm;
    private readonly byte[] _salt;
    private readonly int _iterations;

    public Pbkdf2KeyNormalizer(
        HashAlgorithmName hashAlgorithm,
        byte[] salt,
        int iterations = 100_000
    )
    {
        _hashAlgorithm = hashAlgorithm;
        _salt = salt;
        _iterations = iterations;
    }

    public byte[] Normalize(byte[] key, int keySize)
    {
        var output = new byte[keySize];
        Rfc2898DeriveBytes.Pbkdf2(key, _salt, output, _iterations, _hashAlgorithm);

        return output;
    }
}
#endif
