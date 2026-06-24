using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SHAKE-256 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Shake256Impl : IHashProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Shake256Impl"/>.
    /// </summary>
    public static readonly Shake256Impl Shared = new();

    private Shake256Impl() { }

    /// <inheritdoc />
    public byte[] Hash(byte[] message)
    {
        return Hash(message, 64); // Standard default output size is 64 bytes (512 bits)
    }

    /// <summary>
    /// Computes the SHAKE-256 hash of the specified message with a custom output length.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="outputLength">The custom output length in bytes.</param>
    /// <returns>The computed hash bytes.</returns>
    public byte[] Hash(byte[] message, int outputLength)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        var digest = new ShakeDigest(256);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[outputLength];
        digest.OutputFinal(result, 0, outputLength);

        return result;
    }
}
