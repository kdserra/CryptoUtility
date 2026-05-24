namespace CryptoUtility.Tests;

public sealed class Sha512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha512Impl();
}
