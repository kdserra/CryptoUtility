using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class HmacSha256Impl : IMacProvider
{
    public static readonly HmacSha256Impl Shared = new();
    public int RequiredKeySizeInBytes => 0;
    public int MacSizeInBytes => 32;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACSHA256(key);

        return hmac.ComputeHash(message);
    }
}
