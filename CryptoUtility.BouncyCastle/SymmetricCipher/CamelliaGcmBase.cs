using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle Camellia-GCM implementations.
/// </summary>
public abstract class CamelliaGcmBase : GcmCipherBase
{
    /// <inheritdoc />
    protected override IBlockCipher CreateEngine() => new CamelliaEngine();
}
