namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha1Impl : ShaBase
{
    public Sha1Impl()
        : base(ShaVariant.Sha1) { }
}
