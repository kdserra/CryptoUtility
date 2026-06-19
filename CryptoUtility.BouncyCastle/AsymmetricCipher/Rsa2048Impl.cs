namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa2048Impl : RsaBase
{
    public static readonly Rsa2048Impl Shared = new();

    public override int KeySizeBytes => 128;

    public override int SaltSizeBytes => 20;
}
