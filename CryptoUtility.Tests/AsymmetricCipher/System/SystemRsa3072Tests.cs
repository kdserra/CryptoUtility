using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemRsa3072Tests : AsymmetricCipherTests
{
    public override IAsymmetricCipher Cipher => Rsa3072Impl.Shared;
}
