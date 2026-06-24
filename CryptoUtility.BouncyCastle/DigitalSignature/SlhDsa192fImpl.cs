using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SLH-DSA-SHA2-192f Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class SlhDsa192fImpl : SlhDsaBase
{
    /// <summary>
    /// The shared SLH-DSA-SHA2-192f instance.
    /// </summary>
    public static readonly SlhDsa192fImpl Shared = new();

    private SlhDsa192fImpl()
        : base(SlhDsaParameters.slh_dsa_sha2_192f) { }
}
