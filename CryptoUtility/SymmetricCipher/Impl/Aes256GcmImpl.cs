namespace CryptoUtility;

/// <summary>
/// Official .NET AES-256 GCM
/// </summary>
[GenerateStaticApi]
internal sealed class Aes256GcmImpl : AesGcmBase
{
    /// <inheritdoc cref="SymmetricCipher.CipherID" />
    public override SymmetricCipherID CipherID => SymmetricCipherID.Aes256GcmSystem;

    /// <inheritdoc cref="SymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 32; // 256-bit

    /// <inheritdoc cref="SymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12; // 96-bit

    /// <inheritdoc cref="SymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16; // 128-bit
}
