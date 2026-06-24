using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Blake2b Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Blake2bImpl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Blake2bImpl"/>.
    /// </summary>
    public static readonly Blake2bImpl Shared = new();

    private Blake2bImpl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);

        var digest = new Blake2bDigest();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
