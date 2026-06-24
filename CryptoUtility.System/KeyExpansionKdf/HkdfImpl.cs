#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// System implementation of HKDF.
/// </summary>
[GenerateStaticApi]
public sealed class HkdfImpl : IKeyExpansionKdf
{
    /// <summary>
    /// Shared static instance of <see cref="HkdfImpl"/>.
    /// </summary>
    public static readonly HkdfImpl Shared = new();

    private HkdfImpl() { }

    /// <inheritdoc />
    public byte[] DeriveKey(byte[] inputKeyMaterial, int outputLength, byte[] salt, byte[] info)
    {
        return DeriveKey(inputKeyMaterial, outputLength, salt, info, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Derives a key of the specified length using a custom hash algorithm.
    /// </summary>
    /// <param name="inputKeyMaterial">The input key material.</param>
    /// <param name="outputLength">The output key length in bytes.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="info">The context info bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>A byte array containing the derived key.</returns>
    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int outputLength,
        byte[] salt,
        byte[] info,
        HashAlgorithmName hashAlgorithm
    )
    {
        LibraryHelper.ThrowIfAnyNull(inputKeyMaterial, salt);
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        return HKDF.DeriveKey(hashAlgorithm, inputKeyMaterial, outputLength, salt, info);
    }
}
#endif
