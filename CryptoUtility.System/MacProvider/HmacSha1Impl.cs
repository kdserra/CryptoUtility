using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class HmacSha1Impl : IMacProvider
{
    public static readonly HmacSha1Impl Shared = new();
    public int RequiredKeySizeInBytes => 0;
    public int MacSizeInBytes => 20;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACSHA1(key);

        return hmac.ComputeHash(message);
    }
}
