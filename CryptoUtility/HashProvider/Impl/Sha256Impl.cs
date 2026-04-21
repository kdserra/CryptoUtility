namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha256Impl : ShaBase
{
    public Sha256Impl()
        : base(ShaVariant.Sha256) { }
}
