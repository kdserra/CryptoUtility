using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class HmacSha1Impl : IMacProvider
{
    public static readonly HmacSha1Impl Shared = new();

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);
        using var hmac = new HMACSHA1(key);

        return hmac.ComputeHash(message);
    }
}
