using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace CryptoUtility;

/// <summary>
/// Provides functionality to derive a normalized cryptographic key using the PBKDF2 algorithm.
/// </summary>
/// <remarks>
/// This implementation uses the Microsoft.AspNetCore.Cryptography.KeyDerivation Pbkdf2
/// implementation which supports all .NET versions, but requires the
/// Microsoft.AspNetCore.Cryptography.KeyDerivation package.
/// </remarks>
public sealed class Pbkdf2KeyNormalizer2 : IKeyNormalizer
{
    private HashAlgorithmName _hashAlgorithm;
    private readonly byte[] _salt;
    private readonly int _iterations;

    public Pbkdf2KeyNormalizer2(
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
        string password = Convert.ToBase64String(key);

        byte[] hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: _salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: _iterations,
            numBytesRequested: keySize
        );

        return output;
    }
}
