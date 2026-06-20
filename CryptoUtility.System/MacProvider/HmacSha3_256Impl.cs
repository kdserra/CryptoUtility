#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class HmacSha3_256Impl : IMacProvider
{
    public static readonly HmacSha3_256Impl Shared = new();
    public int RequiredKeySizeInBytes => 0;
    public int MacSizeInBytes => 32;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACSHA3_256(key);

        return hmac.ComputeHash(message);
    }
}

#endif
