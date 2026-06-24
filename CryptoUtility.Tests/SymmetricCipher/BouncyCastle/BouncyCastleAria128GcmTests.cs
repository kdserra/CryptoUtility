using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleAria128GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aria128GcmImpl.Shared;
}
