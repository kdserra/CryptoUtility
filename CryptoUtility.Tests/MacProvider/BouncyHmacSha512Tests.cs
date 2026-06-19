using BouncyHmacSha512Impl = CryptoUtility.BouncyCastle.HmacSha512Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacSha512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacSha512Impl.Shared;
}
