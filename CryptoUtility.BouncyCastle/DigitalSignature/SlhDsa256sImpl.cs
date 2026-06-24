using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SLH-DSA-SHA2-256s Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class SlhDsa256sImpl : SlhDsaBase
{
    /// <summary>
    /// The shared SLH-DSA-SHA2-256s instance.
    /// </summary>
    public static readonly SlhDsa256sImpl Shared = new();

    private SlhDsa256sImpl()
        : base(SlhDsaParameters.slh_dsa_sha2_256s) { }
}
