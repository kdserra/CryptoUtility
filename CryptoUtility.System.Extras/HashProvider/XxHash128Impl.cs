using SystemXxHash128 = System.IO.Hashing.XxHash128;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash128 implementation by wrapping System.IO.Hashing.XxHash128.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash128Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash128Impl"/>.
    /// </summary>
    public static readonly XxHash128Impl Shared = new();

    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);
        return SystemXxHash128.Hash(message);
    }
}
