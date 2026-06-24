using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Whirlpool Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class WhirlpoolImpl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="WhirlpoolImpl"/>.
    /// </summary>
    public static readonly WhirlpoolImpl Shared = new();

    private WhirlpoolImpl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);

        var digest = new WhirlpoolDigest();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
