#if NET8_0_OR_GREATER
namespace CryptoUtility;

internal sealed class Rsa3072Impl : RsaBase
{
    // SHA-384
    public override int SaltSizeBytes => 48; // 384 bits

    public Rsa3072Impl()
        : base(RsaKeySizeBits.KeySize_3072) { }
}

#endif
