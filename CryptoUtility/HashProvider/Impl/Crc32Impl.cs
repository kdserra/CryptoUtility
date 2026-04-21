namespace CryptoUtility.Extras;

/// <summary>
/// Provides an implementation of the CRC32 hashing algorithm for calculating 32-bit cyclic redundancy checks.
/// </summary>
[GenerateStaticApi]
internal sealed class Crc32Impl : CrcBase
{
    public Crc32Impl()
        : base(CrcVariant.Crc32) { }
}
