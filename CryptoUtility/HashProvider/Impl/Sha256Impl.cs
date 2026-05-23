namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha256Impl : ShaBase
{
    internal static readonly Sha256Impl Shared = new();

    public Sha256Impl()
        : base(ShaVariant.Sha256) { }
}
