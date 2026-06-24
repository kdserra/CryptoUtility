namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle Camellia-256 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Camellia256GcmImpl : CamelliaGcmBase
{
    /// <summary>
    /// Shared static instance of <see cref="Camellia256GcmImpl"/>.
    /// </summary>
    public static readonly Camellia256GcmImpl Shared = new();

    private Camellia256GcmImpl() { }

    /// <inheritdoc />
    public override int KeySizeBytes => 32;

    /// <inheritdoc />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc />
    public override int AuthTagSizeBytes => 16;
}
