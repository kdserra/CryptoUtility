namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa1024Impl : RsaBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Rsa1024Impl Shared = new();

    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>
    public override int KeySizeBytes => 128;

    /// <summary>
    /// Gets the salt size in bytes.
    /// </summary>
    public override int SaltSizeBytes => 20;
}
