using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleCamellia256GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Camellia256GcmImpl.Shared;
}
