namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa4096Impl : RsaBase
{
    public static readonly Rsa4096Impl Shared = new();

    public override int KeySizeBytes => 128;

    public override int SaltSizeBytes => 20;
}
