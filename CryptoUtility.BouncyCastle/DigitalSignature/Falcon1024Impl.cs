namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle FALCON-1024 Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Falcon1024Impl : FalconBase
{
    /// <summary>
    /// The shared FALCON-1024 instance.
    /// </summary>
    public static readonly Falcon1024Impl Shared = new();

    private Falcon1024Impl() : base(Org.BouncyCastle.Pqc.Crypto.Falcon.FalconParameters.falcon_1024) { }
}
