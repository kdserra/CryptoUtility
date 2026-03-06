namespace CryptoUtility;

public sealed class Sha256HashProvider : ShaHashProvider
{
    public Sha256HashProvider()
        : base(ShaVariant.Sha256) { }
}
