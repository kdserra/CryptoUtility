namespace CryptoUtility;

public sealed class Sha512HashProvider : ShaHashProvider
{
    public Sha512HashProvider()
        : base(ShaVariant.Sha512) { }
}
