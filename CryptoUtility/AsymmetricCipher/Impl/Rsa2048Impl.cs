#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Rsa2048Impl : RsaBase
{
    public static readonly Rsa2048Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 256;

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 32;
}

#endif
