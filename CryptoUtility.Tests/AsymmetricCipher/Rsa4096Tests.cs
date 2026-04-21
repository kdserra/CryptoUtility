namespace CryptoUtility.Tests;

public sealed class Rsa4096Tests : AsymmetricCipherTests
{
    internal override AsymmetricCipher Cipher => new Rsa4096Impl();
}
