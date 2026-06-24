using SystemXxHash32 = System.IO.Hashing.XxHash32;

namespace CryptoUtility.System.Extras;

/// <summary>
/// Provides a XxHash32 checksum implementation by wrapping <see cref="System.IO.Hashing.XxHash32"/>.
/// </summary>
[GenerateStaticApi]
public sealed class XxHash32Impl : IChecksumProvider
{
    /// <summary>
    /// The shared static instance of <see cref="XxHash32Impl"/>.
    /// </summary>
    public static readonly XxHash32Impl Shared = new();

    private XxHash32Impl() { }

    /// <inheritdoc />
    public int ChecksumSizeInBytes => 4;

    /// <inheritdoc />
    public byte[] ComputeChecksum(byte[] data)
    {
        LibraryHelper.ThrowIfAnyNull(data);
        return SystemXxHash32.Hash(data);
    }
}
