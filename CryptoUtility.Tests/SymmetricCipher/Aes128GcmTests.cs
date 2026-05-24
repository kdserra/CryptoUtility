namespace CryptoUtility.Tests;

public sealed class Aes128GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => new Aes128GcmImpl();
}
