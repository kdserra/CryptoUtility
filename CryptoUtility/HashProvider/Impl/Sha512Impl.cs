namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha512Impl : ShaBase
{
    public static readonly Sha512Impl Shared = new();

    public Sha512Impl()
        : base(ShaVariant.Sha512) { }
}
