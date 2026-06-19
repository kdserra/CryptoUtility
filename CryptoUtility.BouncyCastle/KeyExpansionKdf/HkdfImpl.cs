using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

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
        return DeriveKey(
            inputKeyMaterial,
            iterations,
            outputLength,
            salt,
            info,
            new Sha256Digest()
        );
    }

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info,
        IDigest digest
    )
    {
        LibraryHelper.ThrowIfAnyNull(inputKeyMaterial, salt);

        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        HkdfBytesGenerator hkdf = new(digest);
        hkdf.Init(new HkdfParameters(inputKeyMaterial, salt, info));

        byte[] result = new byte[outputLength];
        hkdf.GenerateBytes(result, 0, outputLength);

        return result;
    }
}
