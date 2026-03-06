using System.IO.Hashing;

namespace CryptoUtility;

public abstract class XxHashHashProvider : IHashProvider
{
    public enum XxHashVariant
    {
        XxHash32,
        XxHash64,
        XxHash128,
    }

    private readonly XxHashVariant _variant;

    protected XxHashHashProvider(XxHashVariant variant)
    {
        _variant = variant;
    }

    public byte[] Hash(byte[] input)
    {
        return _variant switch
        {
            XxHashVariant.XxHash32 => XxHash32.Hash(input),
            XxHashVariant.XxHash64 => XxHash64.Hash(input),
            XxHashVariant.XxHash128 => XxHash128.Hash(input),
            _ => throw new NotSupportedException(),
        };
    }

    public byte[] Sign(byte[] input, byte[] key)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key must not be empty.", nameof(key));

        byte[] combined = new byte[key.Length + input.Length];
        Buffer.BlockCopy(key, 0, combined, 0, key.Length);
        Buffer.BlockCopy(input, 0, combined, key.Length, input.Length);

        return Hash(combined);
    }

    public bool VerifySignature(byte[] input, byte[] signature, byte[] key)
    {
        var computed = Sign(input, key);
        var result = CryptoHelper.FixedTimeEquals(computed, signature);
        return result;
    }
}
