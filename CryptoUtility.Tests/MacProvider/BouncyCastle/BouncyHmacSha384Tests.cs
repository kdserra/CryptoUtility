using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacSha384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha384Impl.Shared;
}
