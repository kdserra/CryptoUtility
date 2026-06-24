using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SLH-DSA-SHA2-128s Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class SlhDsa128sImpl : SlhDsaBase
{
    /// <summary>
    /// The shared SLH-DSA-SHA2-128s instance.
    /// </summary>
    public static readonly SlhDsa128sImpl Shared = new();

    private SlhDsa128sImpl()
        : base(SlhDsaParameters.slh_dsa_sha2_128s) { }
}
