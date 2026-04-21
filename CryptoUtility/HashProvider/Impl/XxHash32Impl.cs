namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class XxHash32Impl : XxHashBase
{
    public XxHash32Impl()
        : base(XxHashVariant.XxHash32) { }
}
