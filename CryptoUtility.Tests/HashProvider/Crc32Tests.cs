namespace CryptoUtility.Tests;

public sealed class Crc32Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Crc32Impl();
}
