namespace CryptoUtility.Tests;

public sealed class XxHash64Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new XxHash64Impl();
}
