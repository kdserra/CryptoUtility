namespace CryptoUtility;

public sealed class Sha1 : ShaHashProvider
{
    public static readonly Sha1 Shared = new();

    public Sha1()
        : base(ShaVariant.Sha1) { }
}
