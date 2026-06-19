using BouncyHmacSha256Impl = CryptoUtility.BouncyCastle.HmacSha256Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha256Impl.Shared;
}
