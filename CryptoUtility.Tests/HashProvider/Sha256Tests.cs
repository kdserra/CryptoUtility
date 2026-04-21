namespace CryptoUtility.Tests;

public sealed class Sha256Tests : HashProviderTests
{
    internal override HashProvider HashProvider => new Sha256Impl();
}
