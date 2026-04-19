namespace CryptoUtility;

public sealed class Sha512 : ShaHashProvider
{
    public static readonly Sha512 Shared = new();

    public Sha512()
        : base(ShaVariant.Sha512) { }
}
