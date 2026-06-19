using BouncyHmacSha3_512Impl = CryptoUtility.BouncyCastle.HmacSha3_512Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha3_512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha3_512Impl.Shared;
}
