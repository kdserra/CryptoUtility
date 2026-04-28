namespace CryptoUtility.Tests;

public sealed class Sha256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha256Impl();
}
