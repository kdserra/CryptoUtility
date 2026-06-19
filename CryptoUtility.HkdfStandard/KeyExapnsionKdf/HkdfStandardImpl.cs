using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// HKDF.Standard library implementation of HKDF, highly backwards compatible unlike the official .NET HKDF.
/// https://github.com/andreimilto/HKDF.Standard
/// </summary>
[GenerateStaticApi]
public class HkdfStandardImpl : IKeyExpansionKdf
{
    public static readonly HkdfStandardImpl Shared = new();

    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

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

        return global::HkdfStandard.Hkdf.DeriveKey(
            DefaultHashAlgorithm,
            inputKeyMaterial,
            outputLength,
            salt,
            info
        );
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

        return global::HkdfStandard.Hkdf.DeriveKey(
            hashAlgorithm,
            inputKeyMaterial,
            outputLength,
            salt,
            info
        );
    }
}
