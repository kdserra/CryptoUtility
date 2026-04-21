namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha384Impl : ShaBase
{
    internal static readonly Sha384Impl Shared = new();

    public Sha384Impl()
        : base(ShaVariant.Sha384) { }
}
