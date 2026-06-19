using BouncyHmacSha384Impl = CryptoUtility.BouncyCastle.HmacSha384Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha384Impl.Shared;
}
