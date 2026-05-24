namespace CryptoUtility.Tests;

public sealed class Sha3_384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_384Impl();
}
