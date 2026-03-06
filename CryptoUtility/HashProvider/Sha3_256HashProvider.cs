namespace CryptoUtility;

#if NET8_0_OR_GREATER
public sealed class Sha3_256HashProvider : ShaHashProvider
{
    public Sha3_256HashProvider()
        : base(ShaVariant.Sha3_256) { }
}
#endif
