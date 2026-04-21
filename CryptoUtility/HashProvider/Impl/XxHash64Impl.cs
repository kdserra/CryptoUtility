namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class XxHash64Impl : XxHashBase
{
    internal static readonly XxHash64Impl Shared = new();

    public XxHash64Impl()
        : base(XxHashVariant.XxHash64) { }
}
