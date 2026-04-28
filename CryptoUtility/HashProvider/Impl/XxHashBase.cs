using XxHash128System = System.IO.Hashing.XxHash128;
using XxHash32System = System.IO.Hashing.XxHash32;
using XxHash64System = System.IO.Hashing.XxHash64;

namespace CryptoUtility.Extras;

public abstract class XxHashBase : IHashProvider
{
    public enum XxHashVariant
    {
        XxHash32,
        XxHash64,
        XxHash128,
    }

    private readonly XxHashVariant _variant;

    protected XxHashBase(XxHashVariant variant)
    {
        _variant = variant;
    }

    public override byte[] Hash(byte[] message)
    {
        return _variant switch
        {
            XxHashVariant.XxHash32 => XxHash32System.Hash(message),
            XxHashVariant.XxHash64 => XxHash64System.Hash(message),
            XxHashVariant.XxHash128 => XxHash128System.Hash(message),
            _ => throw new NotSupportedException(),
        };
    }
}
