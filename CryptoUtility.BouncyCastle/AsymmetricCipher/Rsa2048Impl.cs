namespace CryptoUtility.BouncyCastle;

/// <inheritdoc cref="RsaBase"/>
[GenerateStaticApi]
public sealed class Rsa2048Impl : RsaBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Rsa2048Impl Shared = new();
    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>

    public override int KeySizeBytes => 256;
    /// <summary>
    /// Gets the salt size in bytes.
    /// </summary>

    public override int SaltSizeBytes => 32;
}
