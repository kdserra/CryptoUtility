using System.Text;

namespace CryptoUtility.Tests;

public abstract class SymmetricCipherAEADTests : SymmetricCipherAETests
{
    internal ISymmetricCipherAEAD CipherAEAD => (ISymmetricCipherAEAD)Cipher;

    [Fact]
    public void Encrypt_CheckEnvelopeValidAEAD()
    {
        var key = GenerateKey();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.Encrypt(key, plaintext);

        Assert.NotNull(encrypted);
        
        int nonceLen = CipherAEAD.NonceSizeBytes;
        int tagLen = CipherAEAD.AuthTagSizeBytes;
        Assert.True(encrypted.Length >= nonceLen + tagLen);
        
        byte[] tag = new byte[tagLen];
        Buffer.BlockCopy(encrypted, encrypted.Length - tagLen, tag, 0, tagLen);

        Assert.NotEmpty(tag);
        Assert.Equal(tagLen, tag.Length);
    }

    [Fact]
    public void Encrypt_WithNonceAndAad_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("aad test");
        var nonce = new byte[Cipher.NonceSizeBytes];
        var aad = Encoding.UTF8.GetBytes("associated data");

        new Random().NextBytes(nonce);

        var encrypted = CipherAEAD.Encrypt(key, plaintext, nonce, aad);

        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithNonceAndAad_RoundTrip()
    {
        var key = CipherAEAD.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("roundtrip aad");
        var nonce = new byte[Cipher.NonceSizeBytes];
        var aad = Encoding.UTF8.GetBytes("aad");

        new Random().NextBytes(nonce);

        var encrypted = CipherAEAD.Encrypt(key, plaintext, nonce, aad);
        var decrypted = CipherAEAD.Decrypt(key, encrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }
}
