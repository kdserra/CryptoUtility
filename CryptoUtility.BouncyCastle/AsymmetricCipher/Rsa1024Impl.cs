namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa1024Impl : RsaBase
{
    public static readonly Rsa1024Impl Shared = new();

    public override int KeySizeBytes => 128;

    public override int SaltSizeBytes => 20;
}
