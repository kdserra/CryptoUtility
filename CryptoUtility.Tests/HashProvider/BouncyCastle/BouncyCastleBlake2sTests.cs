using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBlake2sTests : HashProviderTests
{
    internal override IHashProvider HashProvider => Blake2sImpl.Shared;
}
