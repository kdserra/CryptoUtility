using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasCrc64Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Crc64Impl();
}
