using CryptoUtility.NaCl;

namespace CryptoUtility.Tests;

public sealed class NaClChaCha20Tests : SymmetricCipherTests
{
    internal override ISymmetricCipher Cipher => new ChaCha20Impl();
}
