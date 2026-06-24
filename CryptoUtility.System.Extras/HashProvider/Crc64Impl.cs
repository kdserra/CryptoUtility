using SystemCrc64 = System.IO.Hashing.Crc64;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a CRC64 checksum implementation by wrapping <see cref="System.IO.Hashing.Crc64"/>.
/// </summary>
[GenerateStaticApi]
public sealed class Crc64Impl : IChecksumProvider
{
    /// <summary>
    /// The shared static instance of <see cref="Crc64Impl"/>.
    /// </summary>
    public static readonly Crc64Impl Shared = new();

    private Crc64Impl() { }

    /// <inheritdoc />
    public int ChecksumSizeInBytes => 8;

    /// <inheritdoc />
    public byte[] ComputeChecksum(byte[] data)
    {
        LibraryHelper.ThrowIfAnyNull(data);
        return SystemCrc64.Hash(data);
    }
}
