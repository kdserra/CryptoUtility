using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleKmac256Tests : MacProviderTests
{
    internal override IMacProvider Mac => Kmac256Impl.Shared;
}
