using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha384Impl();
}
