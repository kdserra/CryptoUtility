using BouncyHmacMd5Impl = CryptoUtility.BouncyCastle.HmacMd5Impl;

namespace CryptoUtility.Tests;

public class BouncyHmacMd5Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = BouncyHmacMd5Impl.Shared;
}
