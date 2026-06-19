using BouncySha3_384Impl = CryptoUtility.BouncyCastle.Sha3_384Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha3_384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha3_384Impl();
}
