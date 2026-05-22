#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Rsa1024Impl : RsaBase
{
    internal static readonly Rsa1024Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 128;

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 20;
}

#endif
