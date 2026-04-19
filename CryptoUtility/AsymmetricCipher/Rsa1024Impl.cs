#if NET8_0_OR_GREATER
namespace CryptoUtility;

internal sealed class Rsa1024Impl : RsaBase
{
    // SHA-1
    public override int SaltSizeBytes => 20; // 160 bits

    public Rsa1024Impl()
        : base(RsaKeySizeBits.KeySize_1024) { }
}

#endif
