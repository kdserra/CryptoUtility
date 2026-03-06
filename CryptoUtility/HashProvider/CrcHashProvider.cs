using System;
using System.IO.Hashing;

namespace CryptoUtility;

public abstract class CrcHashProvider : IHashProvider
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

    public byte[] Hash(byte[] input)
    {
        return _variant switch
        {
            CrcVariant.Crc32 => Crc32.Hash(input),
            CrcVariant.Crc64 => Crc64.Hash(input),
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
        return CryptoHelper.FixedTimeEquals(computed, signature);
    }
}
