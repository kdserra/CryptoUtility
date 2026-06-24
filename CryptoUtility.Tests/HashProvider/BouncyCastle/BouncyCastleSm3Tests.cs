using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSm3Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sm3Impl.Shared;
}
