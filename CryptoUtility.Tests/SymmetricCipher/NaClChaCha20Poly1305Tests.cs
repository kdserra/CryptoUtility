using CryptoUtility.NaCl;

namespace CryptoUtility.Tests;

public sealed class NaClChaCha20Poly1305Tests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => new ChaCha20Poly1305Impl();
}
