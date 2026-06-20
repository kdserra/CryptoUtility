using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyMd5Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Md5Impl.Shared;
}
