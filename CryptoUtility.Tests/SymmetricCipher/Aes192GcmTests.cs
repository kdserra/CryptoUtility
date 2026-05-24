namespace CryptoUtility.Tests;

public sealed class Aes192GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => new Aes192GcmImpl();
}
