namespace CryptoUtility.BouncyCastle;

/// <summary>
/// BouncyCastle ARIA-192 GCM
/// </summary>
[GenerateStaticApi]
public sealed class Aria192GcmImpl : AriaGcmBase
{
    /// <summary>
    /// Shared static instance of <see cref="Aria192GcmImpl"/>.
    /// </summary>
    public static readonly Aria192GcmImpl Shared = new();

    private Aria192GcmImpl() { }

    /// <inheritdoc />
    public override int KeySizeBytes => 24;

    /// <inheritdoc />
    public override int NonceSizeBytes => 12;

    /// <inheritdoc />
    public override int AuthTagSizeBytes => 16;
}
