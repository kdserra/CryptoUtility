namespace CryptoUtility.Tests;

public sealed class XxHash128Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new XxHash128Impl();
}
