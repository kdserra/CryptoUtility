using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using BouncyHmac = Org.BouncyCastle.Crypto.Macs.HMac;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HMAC-SM3 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSm3Impl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="HmacSm3Impl"/>.
    /// </summary>
    public static readonly HmacSm3Impl Shared = new();

    private HmacSm3Impl() { }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 0;

    /// <inheritdoc />
    public int MacSizeInBytes => 32;

    /// <inheritdoc />
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(message);

        var hmac = new BouncyHmac(new SM3Digest());
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        hmac.DoFinal(output, 0);

        return output;
    }
}
