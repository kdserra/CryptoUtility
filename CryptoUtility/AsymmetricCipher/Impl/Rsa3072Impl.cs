#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Rsa3072Impl : RsaBase
{
    public static readonly Rsa3072Impl Shared = new();

    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public override int KeySizeBytes => 384;

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public override int SaltSizeBytes => 48;
}

#endif
