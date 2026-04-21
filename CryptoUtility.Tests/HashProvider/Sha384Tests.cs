namespace CryptoUtility.Tests;

public sealed class Sha384Tests : HashProviderTests
{
    internal override HashProvider HashProvider => new Sha384Impl();
}
