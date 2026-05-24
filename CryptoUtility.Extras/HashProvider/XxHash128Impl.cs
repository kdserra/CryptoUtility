namespace CryptoUtility;

[GenerateStaticApi]
public sealed class XxHash128Impl : XxHashBase
{
    public static readonly XxHash128Impl Shared = new();

    public XxHash128Impl()
        : base(XxHashVariant.XxHash128) { }
}
