namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class XxHash64Impl : XxHashBase
{
    public XxHash64Impl()
        : base(XxHashVariant.XxHash64) { }
}
