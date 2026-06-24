using SystemXxHash64 = System.IO.Hashing.XxHash64;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash64 implementation by wrapping System.IO.Hashing.XxHash64.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash64Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash64Impl"/>.
    /// </summary>
    public static readonly XxHash64Impl Shared = new();

    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);
        return SystemXxHash64.Hash(message);
    }
}
