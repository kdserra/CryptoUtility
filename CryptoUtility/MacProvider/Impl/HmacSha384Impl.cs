using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class HmacSha384Impl : IMacProvider
{
    public static readonly HmacSha384Impl Shared = new();

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);
        using var hmac = new HMACSHA384(key);

        return hmac.ComputeHash(message);
    }
}
