using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasCrc32Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Crc32Impl.Shared;
}
