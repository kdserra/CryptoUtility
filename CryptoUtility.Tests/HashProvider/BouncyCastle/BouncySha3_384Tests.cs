using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha3_384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha3_384Impl.Shared;
}
