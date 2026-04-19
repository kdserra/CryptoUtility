using System.Text;

namespace CryptoUtility.Tests;

public abstract class SymmetricCipherTests
{
    internal abstract SymmetricCipher Cipher { get; }

    public byte[] GenerateKey()
    {
        return Cipher.GenerateKey();
    }

    public byte[] GeneratePlaintext()
    {
        string message = "Hello, world!";
        byte[] plaintext = Encoding.UTF8.GetBytes(message);
        return plaintext;
    }

    [Fact]
    public void Encrypt_CheckEnvelopeValid()
    {
        var key = GenerateKey();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.Encrypt(key, plaintext);
        Assert.True(okEnc);

        var envelope = SymmetricCipherEnvelope.FromBytes(encrypted);

        Assert.NotNull(envelope);
        Assert.Equal(SymmetricCipherEnvelope.LatestVersion, envelope.Version);

        Assert.NotNull(envelope.Ciphertext);
        Assert.NotEmpty(envelope.Ciphertext);

        Assert.NotNull(envelope.Nonce);
        Assert.NotEmpty(envelope.Nonce);

        // Not required (they are allowed to be empty byte[]), they just can't be null.
        Assert.NotNull(envelope.Tag);
        Assert.NotNull(envelope.Aad);
    }

    [Fact]
    public void EncryptDecrypt_Roundtrip()
    {
        var key = GenerateKey();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.Encrypt(key, plaintext);
        Assert.True(okEnc);

        var (okDec, decrypted) = Cipher.Decrypt(key, encrypted);
        Assert.True(okDec);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void GenerateKey_HasCorrectLength()
    {
        var key = Cipher.GenerateKey();
        Assert.NotNull(key);
        Assert.Equal(Cipher.KeySizeBytes, key.Length);
    }

    [Fact]
    public void GenerateNonce_HasCorrectLength()
    {
        var nonce = Cipher.GenerateNonce();
        Assert.NotNull(nonce);
        Assert.Equal(Cipher.NonceSizeBytes, nonce.Length);
    }

    [Fact]
    public void EncryptDecrypt_RawBytes_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("test message");

        var (encSuccess, encrypted) = Cipher.Encrypt(key, plaintext);
        Assert.True(encSuccess);
        Assert.NotNull(encrypted);

        var (decSuccess, decrypted) = Cipher.Decrypt(key, encrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64_Succeeds()
    {
        var key = Cipher.GenerateKeyBase64();
        var plaintext = "hello world";

        var (encSuccess, encrypted) = Cipher.EncryptBase64(key, plaintext);
        Assert.True(encSuccess);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var (decSuccess, decrypted) = Cipher.DecryptBase64(key, encrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_WithNonce_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("nonce test");
        var nonce = new byte[12];
        new Random().NextBytes(nonce);

        var (success, encrypted) = Cipher.Encrypt(key, plaintext, nonce);

        Assert.True(success);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }
}
