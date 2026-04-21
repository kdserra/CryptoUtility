#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Rsa2048Impl : RsaBase
{
    /// <inheritdoc cref="AsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 256; // 2048 bits

    /// <inheritdoc cref="AsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 32; // 256 bits
}

#endif
