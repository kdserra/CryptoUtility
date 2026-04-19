#if NET8_0_OR_GREATER
namespace CryptoUtility;

internal sealed class Rsa4096Impl : RsaAsymmetricCipher
{
    // SHA-512
    public override int SaltSizeBytes => 64;

    public Rsa4096Impl()
        : base(RsaKeySizeBits.KeySize_4096) { }
}

#endif
