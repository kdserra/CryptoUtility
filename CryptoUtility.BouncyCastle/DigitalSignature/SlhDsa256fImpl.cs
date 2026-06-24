using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SLH-DSA-SHA2-256f Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class SlhDsa256fImpl : SlhDsaBase
{
    /// <summary>
    /// The shared SLH-DSA-SHA2-256f instance.
    /// </summary>
    public static readonly SlhDsa256fImpl Shared = new();

    private SlhDsa256fImpl() : base(SlhDsaParameters.slh_dsa_sha2_256f) { }
}
