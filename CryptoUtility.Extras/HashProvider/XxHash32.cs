namespace CryptoUtility.Extras;

public sealed class XxHash32 : XxHash
{
    public static readonly XxHash32 Shared = new();

    public XxHash32()
        : base(XxHashVariant.XxHash32) { }
}
