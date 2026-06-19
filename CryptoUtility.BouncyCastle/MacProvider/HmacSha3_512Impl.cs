using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using BouncyHmac = Org.BouncyCastle.Crypto.Macs.HMac;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HMAC-SHA3_512 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSha3_512Impl : IMacProvider
{
    public static readonly HmacSha3_512Impl Shared = new();

    public int RequiredKeySizeInBytes => 0;

    public int MacSizeInBytes => 64;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        var hmac = new BouncyHmac(new Sha3Digest(512));
        hmac.Init(new KeyParameter(key));

        hmac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        hmac.DoFinal(output, 0);

        return output;
    }
}
