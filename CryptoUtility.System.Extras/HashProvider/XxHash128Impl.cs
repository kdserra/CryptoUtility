using SystemXxHash128 = System.IO.Hashing.XxHash128;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash128 checksum implementation by wrapping <see cref="System.IO.Hashing.XxHash128"/>.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash128Impl : IChecksumProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash128Impl"/>.
    /// </summary>
    public static readonly XxHash128Impl Shared = new();

    private XxHash128Impl() { }

    /// <inheritdoc />
    public int ChecksumSizeInBytes => 16;

    /// <inheritdoc />
    public byte[] ComputeChecksum(byte[] data)
    {
        LibraryHelper.ThrowIfAnyNull(data);
        return SystemXxHash128.Hash(data);
    }
}
