using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleCamellia192GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Camellia192GcmImpl.Shared;
}
