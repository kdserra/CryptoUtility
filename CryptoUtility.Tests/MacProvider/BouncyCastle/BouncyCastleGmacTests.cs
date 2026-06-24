using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleGmacTests : MacProviderTests
{
    internal override IMacProvider Mac => GmacImpl.Shared;
}
