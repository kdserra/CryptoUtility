#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class HkdfImpl : IKeyExpansionKdf
{
    public static readonly HkdfImpl Shared = new();

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        LibraryHelper.ThrowIfAnyNull(inputKeyMaterial, salt);

        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength, salt, info);
    }

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info,
        HashAlgorithmName hashAlgorithm
    )
    {
        LibraryHelper.ThrowIfAnyNull(inputKeyMaterial, salt);

        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        byte[] key = HKDF.DeriveKey(hashAlgorithm, inputKeyMaterial, outputLength, salt, info);
        return key;
    }
}
#endif
