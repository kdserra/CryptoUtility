namespace CryptoUtility;

#if NET8_0_OR_GREATER
public sealed class Sha3_512HashProvider : ShaHashProvider
{
    public Sha3_512HashProvider()
        : base(ShaVariant.Sha3_512) { }
}
#endif
