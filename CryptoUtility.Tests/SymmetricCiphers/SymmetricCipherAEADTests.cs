using System.Text;

namespace CryptoUtility.Tests;

public abstract class SymmetricCipherAEADTests : SymmetricCipherAETests
{
    internal SymmetricCipherAEAD CipherAEAD => (SymmetricCipherAEAD)Cipher;

    [Fact]
    public void Encrypt_WithNonceAndAad_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("aad test");
        var nonce = new byte[12];
        var aad = Encoding.UTF8.GetBytes("associated data");

        new Random().NextBytes(nonce);

        var (success, encrypted) = CipherAEAD.Encrypt(key, plaintext, nonce, aad);

        Assert.True(success);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithNonceAndAad_RoundTrip()
    {
        var key = CipherAEAD.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("roundtrip aad");
        var nonce = new byte[12];
        var aad = Encoding.UTF8.GetBytes("aad");

        new Random().NextBytes(nonce);

        var (encSuccess, encrypted) = CipherAEAD.Encrypt(key, plaintext, nonce, aad);
        Assert.True(encSuccess);

        var (decSuccess, decrypted) = CipherAEAD.Decrypt(key, encrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }
}
