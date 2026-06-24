namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa3072Impl : RsaBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Rsa3072Impl Shared = new();
    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>

    public override int KeySizeBytes => 384;
    /// <summary>
    /// Gets the salt size in bytes.
    /// </summary>

    public override int SaltSizeBytes => 48;
}
