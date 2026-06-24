using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBlake2sMacTests : MacProviderTests
{
    internal override IMacProvider Mac => Blake2sMacImpl.Shared;
}
