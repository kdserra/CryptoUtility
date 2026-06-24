namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle FALCON-512 Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Falcon512Impl : FalconBase
{
    /// <summary>
    /// The shared FALCON-512 instance.
    /// </summary>
    public static readonly Falcon512Impl Shared = new();

    private Falcon512Impl() : base(Org.BouncyCastle.Pqc.Crypto.Falcon.FalconParameters.falcon_512) { }
}
