namespace CryptoUtility.Tests;

public sealed class Rsa1024Tests : AsymmetricCipherTests
{
    internal override AsymmetricCipher Cipher => new Rsa1024Impl();
}
