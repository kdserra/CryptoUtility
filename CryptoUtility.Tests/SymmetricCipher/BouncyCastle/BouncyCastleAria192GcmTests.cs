using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleAria192GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aria192GcmImpl.Shared;
}
