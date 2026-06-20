using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class HmacMd5Impl : IMacProvider
{
    public static readonly HmacMd5Impl Shared = new();
    public int RequiredKeySizeInBytes => 0;
    public int MacSizeInBytes => 16;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACMD5(key);

        return hmac.ComputeHash(message);
    }
}
