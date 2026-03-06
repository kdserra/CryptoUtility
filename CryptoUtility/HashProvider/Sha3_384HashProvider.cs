namespace CryptoUtility;

#if NET8_0_OR_GREATER
public sealed class Sha3_384HashProvider : ShaHashProvider
{
    public Sha3_384HashProvider()
        : base(ShaVariant.Sha3_384) { }
}
#endif
