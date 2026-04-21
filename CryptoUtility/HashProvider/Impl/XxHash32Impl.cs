namespace CryptoUtility.Extras;

[GenerateStaticApi]
internal sealed class XxHash32Impl : XxHashBase
{
    internal static readonly XxHash32Impl Shared = new();

    public XxHash32Impl()
        : base(XxHashVariant.XxHash32) { }
}
