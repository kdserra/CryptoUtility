using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastlePoly1305Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = Poly1305Impl.Shared;
}
