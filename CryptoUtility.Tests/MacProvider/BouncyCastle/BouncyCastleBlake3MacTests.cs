using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBlake3MacTests : MacProviderTests
{
    internal override IMacProvider Mac => Blake3MacImpl.Shared;
}
