#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Rsa1024Impl : RsaBase
{
    /// <inheritdoc cref="AsymmetricCipher.CipherID"/>
    public override AsymmetricCipherID CipherID => AsymmetricCipherID.Rsa1024System;

    /// <inheritdoc cref="AsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 128; // 1024 bits

    /// <inheritdoc cref="AsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 20; // 160 bits
}

#endif
