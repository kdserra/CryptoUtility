#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Rsa4096Impl : RsaBase
{
    /// <inheritdoc cref="AsymmetricCipher.CipherID"/>
    public override AsymmetricCipherID CipherID => AsymmetricCipherID.Rsa4096System;

    /// <inheritdoc cref="AsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 512; // 4096 bits

    /// <inheritdoc cref="AsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 64; // 512 bits
}

#endif
