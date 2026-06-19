using BouncyHmacSha3_384Impl = CryptoUtility.BouncyCastle.HmacSha3_384Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha3_384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha3_384Impl.Shared;
}
