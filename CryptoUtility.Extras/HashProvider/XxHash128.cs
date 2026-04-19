namespace CryptoUtility.Extras;

public sealed class XxHash128 : XxHashBase
{
    public static readonly XxHash128 Shared = new();

    public XxHash128()
        : base(XxHashVariant.XxHash128) { }
}
