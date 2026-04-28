#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Rsa4096Impl : RsaBase
{
    public static readonly Rsa4096Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.CipherID"/>
    public override AsymmetricCipherID CipherID => AsymmetricCipherID.Rsa4096System;

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 512; // 4096 bits

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 64; // 512 bits
}

#endif
