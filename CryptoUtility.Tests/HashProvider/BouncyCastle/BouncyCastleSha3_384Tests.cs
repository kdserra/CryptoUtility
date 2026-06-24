using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSha3_384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha3_384Impl.Shared;
}
