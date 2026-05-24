namespace CryptoUtility;

[GenerateStaticApi]
public sealed class XxHash32Impl : XxHashBase
{
    public static readonly XxHash32Impl Shared = new();

    public XxHash32Impl()
        : base(XxHashVariant.XxHash32) { }
}
