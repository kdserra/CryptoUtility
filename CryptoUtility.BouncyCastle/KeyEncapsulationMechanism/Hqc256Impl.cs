namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HQC-256 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Hqc256Impl : HqcBase
{
    /// <summary>
    /// The shared HQC-256 instance.
    /// </summary>
    public static readonly Hqc256Impl Shared = new();

    private Hqc256Impl() : base(Org.BouncyCastle.Pqc.Crypto.Hqc.HqcParameters.hqc256) { }
}
