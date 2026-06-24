using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle ARIA-GCM implementations.
/// </summary>
public abstract class AriaGcmBase : GcmCipherBase
{
    /// <inheritdoc />
    protected override IBlockCipher CreateEngine() => new AriaEngine();
}
