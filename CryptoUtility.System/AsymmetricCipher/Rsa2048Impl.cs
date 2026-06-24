#if NET8_0_OR_GREATER
namespace CryptoUtility.System;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa2048Impl : RsaBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Rsa2048Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 256;

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 32;
}

#endif
