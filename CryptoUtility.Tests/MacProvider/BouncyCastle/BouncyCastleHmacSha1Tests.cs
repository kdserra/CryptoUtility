using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleHmacSha1Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha1Impl.Shared;
}
