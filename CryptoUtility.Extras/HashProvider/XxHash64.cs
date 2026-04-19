namespace CryptoUtility.Extras;

public sealed class XxHash64 : XxHashBase
{
    public static readonly XxHash64 Shared = new();

    public XxHash64()
        : base(XxHashVariant.XxHash64) { }
}
