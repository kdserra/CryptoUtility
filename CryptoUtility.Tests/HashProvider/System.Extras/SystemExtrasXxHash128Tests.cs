using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasXxHash128Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new XxHash128Impl();
}
