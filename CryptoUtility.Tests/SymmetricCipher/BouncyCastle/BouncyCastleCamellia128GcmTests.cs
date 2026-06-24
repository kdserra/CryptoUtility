using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleCamellia128GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Camellia128GcmImpl.Shared;
}
