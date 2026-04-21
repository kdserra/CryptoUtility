namespace CryptoUtility.Tests;

public class ChaCha20Poly1305Tests : SymmetricCipherAEADTests
{
    internal override SymmetricCipher Cipher => new ChaCha20Poly1305Impl();
}
