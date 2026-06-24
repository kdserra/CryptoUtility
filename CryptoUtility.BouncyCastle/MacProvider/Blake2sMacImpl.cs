using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Blake2s Keyed MAC Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Blake2sMacImpl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Blake2sMacImpl"/>.
    /// </summary>
    public static readonly Blake2sMacImpl Shared = new();

    private Blake2sMacImpl() { }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 0;

    /// <inheritdoc />
    public int MacSizeInBytes => 32;

    /// <inheritdoc />
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        var digest = new Blake2sDigest(key);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        digest.DoFinal(output, 0);

        return output;
    }
}
