using System.IO.Hashing;
using Crc32System = System.IO.Hashing.Crc32;
using Crc64System = System.IO.Hashing.Crc64;

namespace CryptoUtility;

public abstract class CrcBase : IHashProvider
{
    protected enum CrcVariant
    {
        Crc32,
        Crc64,
    }

    private readonly CrcVariant _variant;

    protected CrcBase(CrcVariant variant)
    {
        _variant = variant;
    }

    public byte[] Hash(byte[] message)
    {
        return _variant switch
        {
            CrcVariant.Crc32 => Crc32System.Hash(message),
            CrcVariant.Crc64 => Crc64System.Hash(message),
            _ => throw new NotSupportedException(),
        };
    }
}
