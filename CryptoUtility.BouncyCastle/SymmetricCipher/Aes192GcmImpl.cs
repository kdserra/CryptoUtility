namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle AES-192 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Aes192GcmImpl : AesGcmBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Aes192GcmImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 24;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16;
}
