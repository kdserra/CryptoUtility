using SystemXxHash64 = System.IO.Hashing.XxHash64;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash64 checksum implementation by wrapping <see cref="System.IO.Hashing.XxHash64"/>.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash64Impl : IChecksumProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash64Impl"/>.
    /// </summary>
    public static readonly XxHash64Impl Shared = new();

    private XxHash64Impl() { }

    /// <inheritdoc />
    public int ChecksumSizeInBytes => 8;

    /// <inheritdoc />
    public byte[] ComputeChecksum(byte[] data)
    {
        LibraryHelper.ThrowIfAnyNull(data);
        return SystemXxHash64.Hash(data);
    }
}
