using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBlake2bMacTests : MacProviderTests
{
    internal override IMacProvider Mac => Blake2bMacImpl.Shared;
}
