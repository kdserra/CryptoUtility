using System.Security.Cryptography;

namespace CryptoUtility.HkdfStandard;

/// <summary>
/// HKDF.Standard library implementation of HKDF, highly backwards compatible unlike the official .NET HKDF.
/// https://github.com/andreimilto/HKDF.Standard
/// </summary>
[GenerateStaticApi]
public class HkdfImpl : IKeyExpansionKdf
{
    /// <summary>
    /// Shared static instance of <see cref="HkdfImpl"/>.
    /// </summary>
    public static readonly HkdfImpl Shared = new();

    private HkdfImpl() { }

    /// <inheritdoc />
    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        return DeriveKey(
            inputKeyMaterial,
            outputLength,
            salt,
            info,
            HashAlgorithmName.SHA256
        );
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

        return global::HkdfStandard.Hkdf.DeriveKey(
            hashAlgorithm,
            inputKeyMaterial,
            outputLength,
            salt,
            info
        );
    }
}
