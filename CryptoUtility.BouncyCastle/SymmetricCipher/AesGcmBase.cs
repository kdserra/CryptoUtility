using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle AES-GCM implementations.
/// </summary>
public abstract class AesGcmBase : GcmCipherBase
{
    /// <inheritdoc />
    protected override IBlockCipher CreateEngine() => new AesEngine();
}
