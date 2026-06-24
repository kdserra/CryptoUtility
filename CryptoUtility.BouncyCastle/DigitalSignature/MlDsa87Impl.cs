using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ML-DSA-87 Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class MlDsa87Impl : MlDsaBase
{
    /// <summary>
    /// The shared ML-DSA-87 instance.
    /// </summary>
    public static readonly MlDsa87Impl Shared = new();

    private MlDsa87Impl()
        : base(MLDsaParameters.ml_dsa_87) { }
}
