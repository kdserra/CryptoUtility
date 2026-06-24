namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa4096Impl : RsaBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Rsa4096Impl Shared = new();
    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>

    public override int KeySizeBytes => 512;
    /// <summary>
    /// Gets the salt size in bytes.
    /// </summary>

    public override int SaltSizeBytes => 64;
}
