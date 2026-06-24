using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha384Impl.Shared;
}
