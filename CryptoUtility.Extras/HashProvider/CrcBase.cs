using System.IO.Hashing;
using Crc32System = System.IO.Hashing.Crc32;
using Crc64System = System.IO.Hashing.Crc64;

namespace CryptoUtility.Extras;

public abstract class CrcBase : HashProvider
{
    public enum CrcVariant
    {
        Crc32,
        Crc64,
    }

    private readonly CrcVariant _variant;

    protected CrcBase(CrcVariant variant)
    {
        _variant = variant;
    }

    public override byte[] Hash(byte[] input)
    {
        return _variant switch
        {
            CrcVariant.Crc32 => Crc32System.Hash(input),
            CrcVariant.Crc64 => Crc64System.Hash(input),
            _ => throw new NotSupportedException(),
        };
    }
}
