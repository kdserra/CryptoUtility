#if NET8_0_OR_GREATER
namespace CryptoUtility.System;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa4096Impl : RsaBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Rsa4096Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 512;

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 64;
}

#endif
