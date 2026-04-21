namespace CryptoUtility.Tests;

public sealed class Rsa2048Tests : AsymmetricCipherTests
{
    internal override AsymmetricCipher Cipher => new Rsa2048Impl();
}
