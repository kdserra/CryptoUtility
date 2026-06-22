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

        var envelope = SymmetricCipherEnvelope.FromBytes(encrypted);

        Assert.NotNull(envelope);
        Assert.Equal(SymmetricCipherEnvelope.LatestVersion, envelope.Version);

        Assert.NotNull(envelope.Ciphertext);
        Assert.NotEmpty(envelope.Ciphertext);

        Assert.NotNull(envelope.Nonce);
        Assert.NotEmpty(envelope.Nonce);

        Assert.NotNull(envelope.Tag);
        Assert.NotEmpty(envelope.Tag);

        Assert.NotNull(envelope.Aad);
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
        var decrypted = CipherAEAD.Decrypt(key, encrypted);
        Assert.Equal(plaintext, decrypted);
    }
}
