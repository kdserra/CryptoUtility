using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class HmacSha256Impl : IMacProvider
{
    public static readonly HmacSha256Impl Shared = new();

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);
        using var hmac = new HMACSHA256(key);

        return hmac.ComputeHash(message);
    }
}
