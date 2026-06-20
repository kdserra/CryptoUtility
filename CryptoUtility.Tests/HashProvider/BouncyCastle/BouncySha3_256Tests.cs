using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha3_256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_256Impl();
}
