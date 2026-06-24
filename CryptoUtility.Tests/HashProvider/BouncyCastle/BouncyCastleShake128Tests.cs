using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleShake128Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Shake128Impl.Shared;
}
