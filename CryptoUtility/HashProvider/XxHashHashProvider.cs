using System.IO.Hashing;

namespace CryptoUtility;

public abstract class XxHashHashProvider : HashProvider
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

    public override byte[] Hash(byte[] input)
    {
        return _variant switch
        {
            XxHashVariant.XxHash32 => XxHash32.Hash(input),
            XxHashVariant.XxHash64 => XxHash64.Hash(input),
            XxHashVariant.XxHash128 => XxHash128.Hash(input),
            _ => throw new NotSupportedException(),
        };
    }
}
