using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacSha256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha256Impl.Shared;
}
