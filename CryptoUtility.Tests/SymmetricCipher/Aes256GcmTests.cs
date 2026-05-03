namespace CryptoUtility.Tests;

public sealed class Aes256GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => new Aes256GcmImpl();
}
