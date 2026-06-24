using SystemCrc32 = System.IO.Hashing.Crc32;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a CRC32 checksum implementation by wrapping <see cref="System.IO.Hashing.Crc32"/>.
/// </summary>
[GenerateStaticApi]
public sealed class Crc32Impl : IChecksumProvider
{
    /// <summary>
    /// The shared static instance of <see cref="Crc32Impl"/>.
    /// </summary>
    public static readonly Crc32Impl Shared = new();

    private Crc32Impl() { }

    /// <inheritdoc />
    public int ChecksumSizeInBytes => 4;

    /// <inheritdoc />
    public byte[] ComputeChecksum(byte[] data)
    {
        LibraryHelper.ThrowIfAnyNull(data);
        return SystemCrc32.Hash(data);
    }
}
