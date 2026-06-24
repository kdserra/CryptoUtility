using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleHmacSha512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha512Impl.Shared;
}
