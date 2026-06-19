using BouncySha256Impl = CryptoUtility.BouncyCastle.Sha256Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha256Impl();
}
