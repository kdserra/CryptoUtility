using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleKmac128Tests : MacProviderTests
{
    internal override IMacProvider Mac => Kmac128Impl.Shared;
}
