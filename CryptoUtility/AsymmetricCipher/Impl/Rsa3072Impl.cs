#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Rsa3072Impl : RsaBase
{
    /// <inheritdoc cref="AsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 384; // 3072 bits

    /// <inheritdoc cref="AsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 48; // 384 bits
}

#endif
