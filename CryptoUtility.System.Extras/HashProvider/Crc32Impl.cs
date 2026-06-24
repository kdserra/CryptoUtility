using SystemCrc32 = System.IO.Hashing.Crc32;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a CRC32 implementation by wrapping <see cref="System.IO.Hashing.Crc32"/>.
/// </summary>
[GenerateStaticApi]
public sealed class Crc32Impl : IHashProvider
{
    /// <summary>
    /// The shared static instance of <see cref="Crc32Impl"/>.
    /// </summary>
    public static readonly Crc32Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);
        return SystemCrc32.Hash(message);
    }
}
