namespace CryptoUtility.Tests;

public sealed class Rsa3072Tests : AsymmetricCipherTests
{
    internal override AsymmetricCipher Cipher => new Rsa3072Impl();
}
