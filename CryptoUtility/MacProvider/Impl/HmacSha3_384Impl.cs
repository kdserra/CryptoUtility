#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class HmacSha3_384Impl : IMacProvider
{
    public static readonly HmacSha3_384Impl Shared = new();

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);
        using var hmac = new HMACSHA3_384(key);

        return hmac.ComputeHash(message);
    }
}

#endif
