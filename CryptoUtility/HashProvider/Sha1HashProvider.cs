namespace CryptoUtility;

public sealed class Sha1HashProvider : ShaHashProvider
{
    public Sha1HashProvider()
        : base(ShaVariant.Sha1) { }
}
