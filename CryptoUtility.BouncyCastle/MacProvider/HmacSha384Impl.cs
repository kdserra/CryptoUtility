using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HMAC-SHA384 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSha384Impl : IMacProvider
{
    public static readonly HmacSha384Impl Shared = new();

    public int RequiredKeySizeInBytes => 0;

    public int MacSizeInBytes => 48;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        HMac hmac = new(new Sha384Digest());
        hmac.Init(new KeyParameter(key));

        hmac.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[hmac.GetMacSize()];
        hmac.DoFinal(result, 0);

        return result;
    }
}
