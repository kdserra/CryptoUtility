using Org.BouncyCastle.Crypto.Parameters;
using BouncyHmac = Org.BouncyCastle.Crypto.Macs.HMac;
using BouncyMd5Digest = Org.BouncyCastle.Crypto.Digests.MD5Digest;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HMAC-MD5 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacMd5Impl : IMacProvider
{
    public static readonly HmacMd5Impl Shared = new();

    public int RequiredKeySizeInBytes => 0;

    public int MacSizeInBytes => 16;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        var hmac = new BouncyHmac(new BouncyMd5Digest());
        hmac.Init(new KeyParameter(key));

        hmac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        hmac.DoFinal(output, 0);

        return output;
    }
}
