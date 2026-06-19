using BouncySha1Impl = CryptoUtility.BouncyCastle.Sha1Impl;

namespace CryptoUtility.Tests;

public sealed class BouncySha1Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncySha1Impl();
}
