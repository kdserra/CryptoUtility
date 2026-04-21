namespace CryptoUtility.Extras;

/// <summary>
/// Provides an implementation of the CRC64 hashing algorithm for calculating 64-bit cyclic redundancy checks.
/// </summary>
[GenerateStaticApi]
internal sealed class Crc64Impl : CrcBase
{
    internal static readonly Crc64Impl Shared = new();

    public Crc64Impl()
        : base(CrcVariant.Crc64) { }
}
