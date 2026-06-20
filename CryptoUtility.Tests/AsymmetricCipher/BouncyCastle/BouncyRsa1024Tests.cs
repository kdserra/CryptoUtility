using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyRsa1024Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa1024Impl.Shared;
}
