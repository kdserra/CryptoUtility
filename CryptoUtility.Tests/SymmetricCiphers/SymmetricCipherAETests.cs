using System.Text;

namespace CryptoUtility.Tests;

public abstract class SymmetricCipherAETests : SymmetricCipherTests
{
    internal SymmetricCipherAE CipherAE => (SymmetricCipherAE)Cipher;
}
