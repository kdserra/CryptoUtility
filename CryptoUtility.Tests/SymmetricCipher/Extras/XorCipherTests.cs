using CryptoUtility.Extras;

namespace CryptoUtility.Tests;

public sealed class XorTests : SymmetricCipherTests
{
    internal override ISymmetricCipher Cipher => XorCipherImpl.Shared;
}
