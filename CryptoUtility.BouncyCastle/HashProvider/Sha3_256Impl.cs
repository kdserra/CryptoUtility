using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SHA3_256 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Sha3_256Impl : IHashProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Sha3_256Impl Shared = new();
    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        Sha3Digest digest = new(256);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
