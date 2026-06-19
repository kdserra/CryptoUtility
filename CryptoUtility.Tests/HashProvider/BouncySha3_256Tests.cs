using BouncySha3_256Impl = CryptoUtility.BouncyCastle.Sha3_256Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha3_256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha3_256Impl();
}
