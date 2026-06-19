using BouncyHmacSha1Impl = CryptoUtility.BouncyCastle.HmacSha1Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha1Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha1Impl.Shared;
}
