namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha256Impl : ShaBase
{
    internal static readonly Sha256Impl Shared = new();

    public Sha256Impl()
        : base(ShaVariant.Sha256) { }
}
