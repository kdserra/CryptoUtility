using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SLH-DSA-SHA2-128f Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class SlhDsa128fImpl : SlhDsaBase
{
    /// <summary>
    /// The shared SLH-DSA-SHA2-128f instance.
    /// </summary>
    public static readonly SlhDsa128fImpl Shared = new();

    private SlhDsa128fImpl() : base(SlhDsaParameters.slh_dsa_sha2_128f) { }
}
