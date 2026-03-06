namespace CryptoUtility;

public sealed class Sha384HashProvider : ShaHashProvider
{
    public Sha384HashProvider()
        : base(ShaVariant.Sha384) { }
}
