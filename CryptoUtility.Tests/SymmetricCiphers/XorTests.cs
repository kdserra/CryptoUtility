namespace CryptoUtility.Tests;

public class XorTests : SymmetricCipherTests
{
    internal override SymmetricCipher Cipher => new XorImpl();
}
