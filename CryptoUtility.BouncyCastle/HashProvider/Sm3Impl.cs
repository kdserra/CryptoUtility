using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SM3 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Sm3Impl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Sm3Impl"/>.
    /// </summary>
    public static readonly Sm3Impl Shared = new();

    private Sm3Impl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);

        var digest = new SM3Digest();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
