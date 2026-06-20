using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacSha1Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha1Impl.Shared;
}
