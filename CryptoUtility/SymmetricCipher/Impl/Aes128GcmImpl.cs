namespace CryptoUtility;

/// <summary>
/// Official .NET AES-128 GCM
/// </summary>
[GenerateStaticApi]
internal sealed class Aes128GcmImpl : AesGcmBase
{
    internal static readonly Aes128GcmImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.CipherID" />
    public override SymmetricCipherID CipherID => SymmetricCipherID.Aes128GcmSystem;

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 16; // 128-bit

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12; // 96-bit

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16; // 128-bit
}
