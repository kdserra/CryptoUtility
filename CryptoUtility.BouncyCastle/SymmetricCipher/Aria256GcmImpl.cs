namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle ARIA-256 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Aria256GcmImpl : AriaGcmBase
{
    /// <summary>
    /// Shared static instance of <see cref="Aria256GcmImpl"/>.
    /// </summary>
    public static readonly Aria256GcmImpl Shared = new();

    private Aria256GcmImpl() { }

    /// <inheritdoc />
    public override int KeySizeBytes => 32;

    /// <inheritdoc />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc />
    public override int AuthTagSizeBytes => 16;
}
