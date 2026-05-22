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

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        return global::HkdfStandard.Hkdf.DeriveKey(
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            inputKeyMaterial,
            outputLength,
            salt,
            info
        );
    }
}



