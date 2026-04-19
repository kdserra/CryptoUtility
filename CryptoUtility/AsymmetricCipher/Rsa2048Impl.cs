#if NET8_0_OR_GREATER
namespace CryptoUtility;

internal sealed class Rsa2048Impl : RsaAsymmetricCipher
{
    // SHA-256
    public override int SaltSizeBytes => 32; // 256 bits

    public Rsa2048Impl()
        : base(RsaKeySizeBits.KeySize_2048) { }
}

#endif
