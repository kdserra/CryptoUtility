using BouncyHmacSha3_256Impl = CryptoUtility.BouncyCastle.HmacSha3_256Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha3_256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha3_256Impl.Shared;
}
