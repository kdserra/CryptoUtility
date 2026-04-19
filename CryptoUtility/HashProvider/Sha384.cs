namespace CryptoUtility;

public sealed class Sha384 : ShaHashProvider
{
    public static readonly Sha384 Shared = new();

    public Sha384()
        : base(ShaVariant.Sha384) { }
}
