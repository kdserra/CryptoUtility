using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle RIPEMD-160 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Ripemd160Impl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Ripemd160Impl"/>.
    /// </summary>
    public static readonly Ripemd160Impl Shared = new();

    private Ripemd160Impl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        var digest = new RipeMD160Digest();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
