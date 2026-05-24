using CryptoUtility.NaCl;

namespace CryptoUtility.Tests;

public sealed class NaClXChaCha20Poly1305Tests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => new XChaCha20Poly1305Impl();
}
