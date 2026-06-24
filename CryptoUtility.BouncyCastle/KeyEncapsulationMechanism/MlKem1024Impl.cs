using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ML-KEM-1024 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class MlKem1024Impl : MlKemBase
{
    /// <summary>
    /// The shared ML-KEM-1024 instance.
    /// </summary>
    public static readonly MlKem1024Impl Shared = new();

    private MlKem1024Impl()
        : base(MLKemParameters.ml_kem_1024) { }
}
