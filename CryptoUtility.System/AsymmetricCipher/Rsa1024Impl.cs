#if NET8_0_OR_GREATER
namespace CryptoUtility.System;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa1024Impl : RsaBase
{
    public static readonly Rsa1024Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 128;

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 20;
}

#endif
