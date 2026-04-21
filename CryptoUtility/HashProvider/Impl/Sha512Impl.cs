namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha512Impl : ShaBase
{
    public Sha512Impl()
        : base(ShaVariant.Sha512) { }
}
