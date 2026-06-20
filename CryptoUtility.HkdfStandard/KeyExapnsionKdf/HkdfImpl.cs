using System.Security.Cryptography;

namespace CryptoUtility.HkdfStandard;

/// <summary>
/// HKDF.Standard library implementation of HKDF, highly backwards compatible unlike the official .NET HKDF.
/// https://github.com/andreimilto/HKDF.Standard
/// </summary>
[GenerateStaticApi]
public class HkdfImpl : IKeyExpansionKdf
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
        return DeriveKey(
            inputKeyMaterial,
            iterations,
            outputLength,
            salt,
            info,
            HashAlgorithmName.SHA256
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
