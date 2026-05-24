namespace CryptoUtility.Tests;

public sealed class Crc64Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Crc64Impl();
}
