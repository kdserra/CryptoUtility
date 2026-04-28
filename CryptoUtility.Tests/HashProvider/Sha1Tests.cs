namespace CryptoUtility.Tests;

public sealed class Sha1Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha1Impl();
}
