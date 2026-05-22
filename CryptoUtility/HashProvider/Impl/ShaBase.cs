using System.Security.Cryptography;

namespace CryptoUtility;

public abstract class ShaBase : IHashProvider
{
    public enum ShaVariant
    {
        Sha1,
        Sha256,
        Sha384,
        Sha512,
#if NET8_0_OR_GREATER
        Sha3_256,
        Sha3_384,
        Sha3_512,
#endif
    }

    private readonly ShaVariant _variant;

    protected ShaBase(ShaVariant variant)
    {
        _variant = variant;
    }

    public byte[] Hash(byte[] message)
    {
        using HashAlgorithm alg = CreateHashAlgorithm();
        byte[] hash = alg.ComputeHash(message);
        return hash;
    }

    private HashAlgorithm CreateHashAlgorithm()
    {
        return _variant switch
        {
            ShaVariant.Sha1 => SHA1.Create(),
            ShaVariant.Sha256 => SHA256.Create(),
            ShaVariant.Sha384 => SHA384.Create(),
            ShaVariant.Sha512 => SHA512.Create(),
#if NET8_0_OR_GREATER
            ShaVariant.Sha3_256 => SHA3_256.Create(),
            ShaVariant.Sha3_384 => SHA3_384.Create(),
            ShaVariant.Sha3_512 => SHA3_512.Create(),
#endif
            _ => throw new NotSupportedException(),
        };
    }
}
