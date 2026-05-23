namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class XxHash128Impl : XxHashBase
{
    internal static readonly XxHash128Impl Shared = new();

    public XxHash128Impl()
        : base(XxHashVariant.XxHash128) { }
}
