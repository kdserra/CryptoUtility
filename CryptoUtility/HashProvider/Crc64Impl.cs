namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class Crc64Impl : CrcBase
{
    public Crc64Impl()
        : base(CrcVariant.Crc64) { }
}
