using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ML-DSA-44 Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class MlDsa44Impl : MlDsaBase
{
    /// <summary>
    /// The shared ML-DSA-44 instance.
    /// </summary>
    public static readonly MlDsa44Impl Shared = new();

    private MlDsa44Impl()
        : base(MLDsaParameters.ml_dsa_44) { }
}
