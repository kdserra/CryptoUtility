namespace CryptoUtility.Extras;

public sealed class XxHash32 : XxHashBase
{
    public static readonly XxHash32 Shared = new();

    public XxHash32()
        : base(XxHashVariant.XxHash32) { }
}
