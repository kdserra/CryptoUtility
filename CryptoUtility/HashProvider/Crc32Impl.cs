namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class Crc32Impl : CrcBase
{
    public Crc32Impl()
        : base(CrcVariant.Crc32) { }
}
