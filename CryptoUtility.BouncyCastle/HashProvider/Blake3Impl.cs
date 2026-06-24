using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Blake3 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Blake3Impl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Blake3Impl"/>.
    /// </summary>
    public static readonly Blake3Impl Shared = new();

    private Blake3Impl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        var digest = new Blake3Digest();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
