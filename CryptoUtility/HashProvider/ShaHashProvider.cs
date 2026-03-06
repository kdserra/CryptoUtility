using System.Security.Cryptography;

namespace CryptoUtility;

public abstract class ShaHashProvider : IHashProvider
{
    public enum ShaVariant
    {
        Sha1,
        Sha256,
        Sha384,
        Sha512,
    }

    private readonly ShaVariant _variant;

    protected ShaHashProvider(ShaVariant variant)
    {
        _variant = variant;
    }

    public byte[] Hash(byte[] input)
    {
        using HashAlgorithm alg = CreateHashAlgorithm();
        return alg.ComputeHash(input);
    }

    public byte[] Sign(byte[] input, byte[] key)
    {
        using HMAC hmac = CreateHmac(key);
        return hmac.ComputeHash(input);
    }

    public bool VerifySignature(byte[] input, byte[] signature, byte[] key)
    {
        var computed = Sign(input, key);
        var result = CryptoHelper.FixedTimeEquals(computed, signature);
        return result;
    }

    private HashAlgorithm CreateHashAlgorithm()
    {
        return _variant switch
        {
            ShaVariant.Sha1 => SHA1.Create(),
            ShaVariant.Sha256 => SHA256.Create(),
            ShaVariant.Sha384 => SHA384.Create(),
            ShaVariant.Sha512 => SHA512.Create(),
            _ => throw new NotSupportedException(),
        };
    }

    private HMAC CreateHmac(byte[] key)
    {
        return _variant switch
        {
            ShaVariant.Sha1 => new HMACSHA1(key),
            ShaVariant.Sha256 => new HMACSHA256(key),
            ShaVariant.Sha384 => new HMACSHA384(key),
            ShaVariant.Sha512 => new HMACSHA512(key),
            _ => throw new NotSupportedException(),
        };
    }
}
