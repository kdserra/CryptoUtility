namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha384Impl : ShaBase
{
    public static readonly Sha384Impl Shared = new();

    public Sha384Impl()
        : base(ShaVariant.Sha384) { }
}
