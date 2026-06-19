using BouncySha384Impl = CryptoUtility.BouncyCastle.Sha384Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha384Impl();
}
