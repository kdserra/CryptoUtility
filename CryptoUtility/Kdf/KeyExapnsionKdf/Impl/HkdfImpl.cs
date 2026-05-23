#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

public class HkdfImpl : IKeyExpansionKdf
{
    internal static readonly HkdfImpl Shared = new();
    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        return HKDF.DeriveKey(DefaultHashAlgorithm, inputKeyMaterial, outputLength, salt, info);
    }

    public byte[] DeriveKey(byte[] inputKeyMaterial, byte[] salt, int iterations, int outputLength)
    {
        byte[] key = HKDF.DeriveKey(DefaultHashAlgorithm, inputKeyMaterial, outputLength, salt);
        return key;
    }

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        byte[] salt,
        int iterations,
        int outputLength,
        HashAlgorithmName hashAlgorithm
    )
    {
        byte[] key = HKDF.DeriveKey(hashAlgorithm, inputKeyMaterial, outputLength, salt);
        return key;
    }
}
#endif
