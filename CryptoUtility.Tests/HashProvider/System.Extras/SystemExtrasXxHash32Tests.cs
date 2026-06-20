using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasXxHash32Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => XxHash32Impl.Shared;
}
