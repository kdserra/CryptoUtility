using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha384Impl.Shared;
}
