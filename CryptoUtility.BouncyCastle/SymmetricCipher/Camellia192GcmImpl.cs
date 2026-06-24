namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle Camellia-192 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Camellia192GcmImpl : CamelliaGcmBase
{
    /// <summary>
    /// Shared static instance of <see cref="Camellia192GcmImpl"/>.
    /// </summary>
    public static readonly Camellia192GcmImpl Shared = new();

    private Camellia192GcmImpl() { }

    /// <inheritdoc />
    public override int KeySizeBytes => 24;

    /// <inheritdoc />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc />
    public override int AuthTagSizeBytes => 16;
}
