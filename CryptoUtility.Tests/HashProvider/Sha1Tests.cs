namespace CryptoUtility.Tests;

public sealed class Sha1Tests : HashProviderTests
{
    internal override HashProvider HashProvider => new Sha1Impl();
}
