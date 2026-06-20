using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class Aes192GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aes192GcmImpl.Shared;
}
