using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleAria256GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aria256GcmImpl.Shared;
}
