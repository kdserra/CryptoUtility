namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha1Impl : ShaBase
{
    internal static readonly Sha1Impl Shared = new();

    public Sha1Impl()
        : base(ShaVariant.Sha1) { }
}
