using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using BouncyHmac = Org.BouncyCastle.Crypto.Macs.HMac;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HMAC-SHA1 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSha1Impl : IMacProvider
{
    public static readonly HmacSha1Impl Shared = new();

    public int RequiredKeySizeInBytes => 0;

    public int MacSizeInBytes => 20;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        var hmac = new BouncyHmac(new Sha1Digest());
        hmac.Init(new KeyParameter(key));

        hmac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        hmac.DoFinal(output, 0);

        return output;
    }
}
