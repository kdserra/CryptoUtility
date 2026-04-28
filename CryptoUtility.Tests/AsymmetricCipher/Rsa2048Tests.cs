namespace CryptoUtility.Tests;

public sealed class Rsa2048Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new Rsa2048Impl();
}
