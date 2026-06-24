using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBlake2bTests : HashProviderTests
{
    internal override IHashProvider HashProvider => Blake2bImpl.Shared;
}
