namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle ARIA-128 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Aria128GcmImpl : AriaGcmBase
{
    /// <summary>
    /// Shared static instance of <see cref="Aria128GcmImpl"/>.
    /// </summary>
    public static readonly Aria128GcmImpl Shared = new();

    private Aria128GcmImpl() { }

    /// <inheritdoc />
    public override int KeySizeBytes => 16;

    /// <inheritdoc />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc />
    public override int AuthTagSizeBytes => 16;
}
