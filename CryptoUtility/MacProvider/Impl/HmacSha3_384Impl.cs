#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class HmacSha3_384Impl : IMacProvider
{
    public static readonly HmacSha3_384Impl Shared = new();
    public int RequiredKeySizeInBytes => 0;
    public int MacSizeInBytes => 48;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        using var hmac = new HMACSHA3_384(key);

        return hmac.ComputeHash(message);
    }
}

#endif
