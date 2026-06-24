using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleHmacSm3Tests : MacProviderTests
{
    internal override IMacProvider Mac => HmacSm3Impl.Shared;
}
