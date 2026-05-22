using System.Security.Cryptography;
using HkdfStandard = HkdfStandard.Hkdf;

namespace CryptoUtility;

/// <summary>
/// HKDF.Standard library implementation of HKDF, highly backwards compatible unlike the official .NET HKDF.
/// https://github.com/andreimilto/HKDF.Standard
/// </summary>
[GenerateStaticApi]
public class HkdfStandardImpl : IKeyExpansionKdf
{
    public static HkdfStandardImpl Shared = new();

    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        return HkdfStandard.DeriveKey(
            inputKeyMaterial,
            iterations,
            outputLength,
            salt,
            info,
            DefaultHashAlgorithm
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
        byte[] key = HkdfStandard.DeriveKey(
            inputKeyMaterial,
            iterations,
            outputLength,
            salt,
            info,
            hashAlgorithm
        );

        return key;
    }
}
