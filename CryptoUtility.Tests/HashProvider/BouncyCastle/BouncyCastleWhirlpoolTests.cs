using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleWhirlpoolTests : HashProviderTests
{
    internal override IHashProvider HashProvider => WhirlpoolImpl.Shared;
}
