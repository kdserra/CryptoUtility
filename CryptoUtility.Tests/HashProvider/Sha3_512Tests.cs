namespace CryptoUtility.Tests;

public sealed class Sha3_512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_512Impl();
}
