using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSha3_256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha3_256Impl.Shared;
}
