namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HQC-192 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Hqc192Impl : HqcBase
{
    /// <summary>
    /// The shared HQC-192 instance.
    /// </summary>
    public static readonly Hqc192Impl Shared = new();

    private Hqc192Impl()
        : base(
            Org.BouncyCastle.Pqc.Crypto.Hqc.HqcParameters.hqc192,
            publicKeySizeBytes: 4546,
            secretKeySizeBytes: 4616,
            ciphertextSizeBytes: 8978,
            sharedSecretSizeBytes: 64
        ) { }
}
