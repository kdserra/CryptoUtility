namespace CryptoUtility;

/// <summary>
/// Official .NET AES-256 GCM
/// </summary>
[GenerateStaticApi]
internal sealed class Aes256GcmImpl : AesGcmBase
{
    internal static readonly Aes256GcmImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.CipherID" />
    public override SymmetricCipherID CipherID => SymmetricCipherID.Aes256GcmSystem;

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 32;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16;
}
