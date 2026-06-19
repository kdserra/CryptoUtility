using BouncySha512Impl = CryptoUtility.BouncyCastle.Sha512Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha512Impl();
}
