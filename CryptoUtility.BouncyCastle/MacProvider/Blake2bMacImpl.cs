using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Blake2b Keyed MAC Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Blake2bMacImpl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Blake2bMacImpl"/>.
    /// </summary>
    public static readonly Blake2bMacImpl Shared = new();

    private Blake2bMacImpl() { }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 0;

    /// <inheritdoc />
    public int MacSizeInBytes => 64;

    /// <inheritdoc />
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfNull(key);
        LibraryHelper.ThrowIfNull(message);

        var digest = new Blake2bDigest(key);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        digest.DoFinal(output, 0);

        return output;
    }
}
