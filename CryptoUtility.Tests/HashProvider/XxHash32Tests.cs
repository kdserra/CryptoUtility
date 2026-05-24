namespace CryptoUtility.Tests;

public sealed class XxHash32Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new XxHash32Impl();
}
