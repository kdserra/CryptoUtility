using BouncySha3_512Impl = CryptoUtility.BouncyCastle.Sha3_512Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha3_512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha3_512Impl();
}
