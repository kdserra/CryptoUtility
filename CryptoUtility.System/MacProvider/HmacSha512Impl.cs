using System.Security.Cryptography;

namespace CryptoUtility.System;

[GenerateStaticApi]
public sealed class HmacSha512Impl : IMacProvider
{
    public static readonly HmacSha512Impl Shared = new();
    public int RequiredKeySizeInBytes => 0;
    public int MacSizeInBytes => 64;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACSHA512(key);

        return hmac.ComputeHash(message);
    }
}
