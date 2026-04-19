namespace CryptoUtility.Tests;

public class Aes256GcmTests : SymmetricCipherAEADTests
{
    internal override SymmetricCipher Cipher => new Aes256GcmImpl();
}
