using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleMd5Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Md5Impl.Shared;
}
