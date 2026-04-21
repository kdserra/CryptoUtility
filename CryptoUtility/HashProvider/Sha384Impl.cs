namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha384Impl : ShaBase
{
    public Sha384Impl()
        : base(ShaVariant.Sha384) { }
}
