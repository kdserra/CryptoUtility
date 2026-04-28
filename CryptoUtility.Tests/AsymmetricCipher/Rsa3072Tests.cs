namespace CryptoUtility.Tests;

public sealed class Rsa3072Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => new Rsa3072Impl();
}
