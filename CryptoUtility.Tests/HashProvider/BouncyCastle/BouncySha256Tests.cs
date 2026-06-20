using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha256Impl();
}
