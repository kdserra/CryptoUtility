namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa3072Impl : RsaBase
{
    public static readonly Rsa3072Impl Shared = new();

    public override int KeySizeBytes => 128;

    public override int SaltSizeBytes => 20;
}
