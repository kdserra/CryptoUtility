using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleHmacSha256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha256Impl.Shared;
}
