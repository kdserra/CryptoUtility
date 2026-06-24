using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSha3_512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha3_512Impl.Shared;
}
