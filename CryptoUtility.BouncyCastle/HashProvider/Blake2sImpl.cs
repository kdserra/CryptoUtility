using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Blake2s Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Blake2sImpl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Blake2sImpl"/>.
    /// </summary>
    public static readonly Blake2sImpl Shared = new();

    private Blake2sImpl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        var digest = new Blake2sDigest();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
