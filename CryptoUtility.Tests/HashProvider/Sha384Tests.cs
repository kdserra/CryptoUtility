namespace CryptoUtility.Tests;

public sealed class Sha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha384Impl();
}
