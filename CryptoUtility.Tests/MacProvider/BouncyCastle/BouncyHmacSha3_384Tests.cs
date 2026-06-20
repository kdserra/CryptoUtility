using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacSha3_384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_384Impl.Shared;
}
