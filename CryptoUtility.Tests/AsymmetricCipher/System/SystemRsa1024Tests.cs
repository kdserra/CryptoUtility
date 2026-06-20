using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemRsa1024Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa1024Impl.Shared;
}
