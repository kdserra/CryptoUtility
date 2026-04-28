namespace CryptoUtility.Tests;

public sealed class Rsa1024Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new Rsa1024Impl();
}
