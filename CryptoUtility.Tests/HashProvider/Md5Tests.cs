namespace CryptoUtility.Tests;

public sealed class Md5Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Md5Impl();
}
