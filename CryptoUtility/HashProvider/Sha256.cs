namespace CryptoUtility;

public sealed class Sha256 : ShaHashProvider
{
    public static readonly Sha256 Shared = new();

    public Sha256()
        : base(ShaVariant.Sha256) { }
}
