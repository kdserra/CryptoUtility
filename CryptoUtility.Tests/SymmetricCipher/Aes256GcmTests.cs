namespace CryptoUtility.Tests;

public sealed class Aes256GcmTests : SymmetricCipherAEADTests
{
    internal override SymmetricCipher Cipher => new Aes256GcmImpl();
}
