namespace CryptoUtility.Extras;

/// <summary>
/// Provides an implementation of the CRC32 hashing algorithm for calculating 32-bit cyclic redundancy checks.
/// </summary>
[GenerateStaticApi]
internal sealed class Crc32Impl : CrcBase
{
    internal static readonly Crc32Impl Shared = new();

    public Crc32Impl()
        : base(CrcVariant.Crc32) { }
}
