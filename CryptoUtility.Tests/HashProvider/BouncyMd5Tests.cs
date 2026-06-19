using BouncyMd5Impl = CryptoUtility.BouncyCastle.Md5Impl;

namespace CryptoUtility.Tests;

public sealed class BouncyMd5Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new BouncyMd5Impl();
}
