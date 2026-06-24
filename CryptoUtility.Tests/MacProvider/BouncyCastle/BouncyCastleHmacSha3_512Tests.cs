using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleHmacSha3_512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_512Impl.Shared;
}
