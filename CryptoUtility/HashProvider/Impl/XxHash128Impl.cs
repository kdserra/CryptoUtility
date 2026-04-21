namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class XxHash128Impl : XxHashBase
{
    public XxHash128Impl()
        : base(XxHashVariant.XxHash128) { }
}
