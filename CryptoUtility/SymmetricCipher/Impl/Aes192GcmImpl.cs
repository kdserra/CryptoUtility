namespace CryptoUtility;

/// <summary>
/// Official .NET AES-192 GCM
/// </summary>
[GenerateStaticApi]
internal sealed class Aes192GcmImpl : AesGcmBase
{
    internal static readonly Aes192GcmImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.CipherID" />
    public override SymmetricCipherID CipherID => SymmetricCipherID.Aes192GcmSystem;

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 24; // 192-bit

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12; // 96-bit

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16; // 128-bit
}
