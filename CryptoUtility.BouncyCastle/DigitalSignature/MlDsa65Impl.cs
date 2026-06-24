using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ML-DSA-65 Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class MlDsa65Impl : MlDsaBase
{
    /// <summary>
    /// The shared ML-DSA-65 instance.
    /// </summary>
    public static readonly MlDsa65Impl Shared = new();

    private MlDsa65Impl() : base(MLDsaParameters.ml_dsa_65) { }
}
