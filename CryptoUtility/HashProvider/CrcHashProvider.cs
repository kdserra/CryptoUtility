using System;
using System.IO.Hashing;

namespace CryptoUtility;

public abstract class CrcHashProvider : HashProvider
{
    public enum CrcVariant
    {
        Crc32,
        Crc64,
    }

    private readonly CrcVariant _variant;

    protected CrcHashProvider(CrcVariant variant)
    {
        _variant = variant;
    }

    public override byte[] Hash(byte[] input)
    {
        return _variant switch
        {
            CrcVariant.Crc32 => Crc32.Hash(input),
            CrcVariant.Crc64 => Crc64.Hash(input),
            _ => throw new NotSupportedException(),
        };
    }
}
