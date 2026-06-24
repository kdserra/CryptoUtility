namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HQC-128 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Hqc128Impl : HqcBase
{
    /// <summary>
    /// The shared HQC-128 instance.
    /// </summary>
    public static readonly Hqc128Impl Shared = new();

    private Hqc128Impl()
        : base(Org.BouncyCastle.Pqc.Crypto.Hqc.HqcParameters.hqc128) { }
}
