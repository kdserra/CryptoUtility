using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyMd5Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Md5Impl();
}
