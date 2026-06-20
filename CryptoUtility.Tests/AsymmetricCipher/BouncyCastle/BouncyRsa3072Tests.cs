using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa3072Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa3072Impl.Shared;
}
