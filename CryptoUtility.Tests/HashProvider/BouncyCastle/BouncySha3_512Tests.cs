using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha3_512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_512Impl();
}
