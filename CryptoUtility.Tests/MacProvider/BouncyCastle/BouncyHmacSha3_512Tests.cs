using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacSha3_512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_512Impl.Shared;
}
