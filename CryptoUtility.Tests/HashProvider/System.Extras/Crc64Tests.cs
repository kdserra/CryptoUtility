using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasCrc64Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Crc64Impl.Shared;
}
