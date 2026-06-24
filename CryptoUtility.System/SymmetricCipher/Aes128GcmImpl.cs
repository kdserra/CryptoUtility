namespace CryptoUtility.System;

/// <summary>
/// Official .NET AES-128 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Aes128GcmImpl : AesGcmBase
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly Aes128GcmImpl Shared = new();

    /// <inheritdoc cref="ISymmetricCipher.KeySizeBytes" />
    public override int KeySizeBytes => 16;

    /// <inheritdoc cref="ISymmetricCipher.NonceSizeBytes" />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc cref="ISymmetricCipherAE.AuthTagSizeBytes" />
    public override int AuthTagSizeBytes => 16;
}
