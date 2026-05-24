namespace CryptoUtility.Tests;

public sealed class Sha3_256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_256Impl();
}
