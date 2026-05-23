namespace CryptoUtility;

/// <summary>
/// Official .NET AES-128 GCM
/// </summary>
[GenerateStaticApi]
internal sealed class Aes128GcmImpl : AesGcmBase
{
    internal static readonly Aes128GcmImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 16;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16;
}
