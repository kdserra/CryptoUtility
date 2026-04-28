namespace CryptoUtility.Tests;

public sealed class Rsa4096Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new Rsa4096Impl();
}
