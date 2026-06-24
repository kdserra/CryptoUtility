namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle Camellia-128 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Camellia128GcmImpl : CamelliaGcmBase
{
    /// <summary>
    /// Shared static instance of <see cref="Camellia128GcmImpl"/>.
    /// </summary>
    public static readonly Camellia128GcmImpl Shared = new();

    private Camellia128GcmImpl() { }

    /// <inheritdoc />
    public override int KeySizeBytes => 16;

    /// <inheritdoc />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc />
    public override int AuthTagSizeBytes => 16;
}
