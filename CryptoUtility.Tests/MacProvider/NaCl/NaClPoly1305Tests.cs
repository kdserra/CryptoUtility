using CryptoUtility.NaCl;

namespace CryptoUtility.Tests;

public class NaClPoly1305Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = Poly1305Impl.Shared;
}
