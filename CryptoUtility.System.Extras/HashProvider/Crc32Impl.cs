using SystemCrc32 = System.IO.Hashing.Crc32;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a CRC32 implementation by wrapping System.IO.Hashing.Crc32.
/// </summary>
[GenerateStaticApi]
public sealed class Crc32Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="Crc32Impl"/>.
    /// </summary>
    public static readonly Crc32Impl Shared = new();

    /// <summary>
    /// Computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfNull(message);
        return SystemCrc32.Hash(message);
    }
}
