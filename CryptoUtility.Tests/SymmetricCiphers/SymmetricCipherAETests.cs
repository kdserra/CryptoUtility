using System.Text;

namespace CryptoUtility.Tests;

public abstract class SymmetricCipherAETests : SymmetricCipherTests
{
    internal SymmetricCipherAE CipherAE => (SymmetricCipherAE)Cipher;

    [Fact]
    public void Encrypt_WithNonce_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("nonce test");
        var nonce = new byte[12];
        new Random().NextBytes(nonce);

        var (success, encrypted) = CipherAE.Encrypt(key, plaintext, nonce);

        Assert.True(success);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }
}
