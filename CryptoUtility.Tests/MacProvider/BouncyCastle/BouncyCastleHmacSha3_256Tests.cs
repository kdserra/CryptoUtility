using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleHmacSha3_256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_256Impl.Shared;
}
