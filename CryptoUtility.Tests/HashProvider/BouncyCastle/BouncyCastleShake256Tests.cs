using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleShake256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Shake256Impl.Shared;
}
