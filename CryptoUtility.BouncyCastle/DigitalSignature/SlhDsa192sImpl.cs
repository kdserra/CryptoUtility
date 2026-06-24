using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SLH-DSA-SHA2-192s Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class SlhDsa192sImpl : SlhDsaBase
{
    /// <summary>
    /// The shared SLH-DSA-SHA2-192s instance.
    /// </summary>
    public static readonly SlhDsa192sImpl Shared = new();

    private SlhDsa192sImpl()
        : base(SlhDsaParameters.slh_dsa_sha2_192s) { }
}
