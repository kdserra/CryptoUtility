using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasXxHash64Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new XxHash64Impl();
}
