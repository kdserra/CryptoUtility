using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SHAKE-128 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Shake128Impl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Shake128Impl"/>.
    /// </summary>
    public static readonly Shake128Impl Shared = new();

    private Shake128Impl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        return Hash(message, 32); // Standard default output size is 32 bytes (256 bits)
    }

    /// <summary>
    /// Computes the SHAKE-128 hash of the specified message with a custom output length.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="outputLength">The custom output length in bytes.</param>
    /// <returns>The computed hash bytes.</returns>
    public byte[] Hash(byte[] message, int outputLength)
    {
        LibraryHelper.ThrowIfNull(message);

        var digest = new ShakeDigest(128);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[outputLength];
        digest.OutputFinal(result, 0, outputLength);

        return result;
    }
}
