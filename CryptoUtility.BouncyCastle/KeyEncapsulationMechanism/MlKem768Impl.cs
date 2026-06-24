using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ML-KEM-768 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class MlKem768Impl : MlKemBase
{
    /// <summary>
    /// The shared ML-KEM-768 instance.
    /// </summary>
    public static readonly MlKem768Impl Shared = new();

    private MlKem768Impl()
        : base(MLKemParameters.ml_kem_768) { }
}
