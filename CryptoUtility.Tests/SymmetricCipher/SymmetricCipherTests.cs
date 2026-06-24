using System.Text;
using CryptoUtility;

namespace CryptoUtility.Tests;

public abstract class SymmetricCipherTests
{
    internal abstract ISymmetricCipher Cipher { get; }

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

        var encrypted = Cipher.Encrypt(key, plaintext);

        Assert.NotNull(encrypted);
        
        int nonceLen = Cipher.NonceSizeBytes;
        if (Cipher is ISymmetricCipherAE aeCipher)
        {
            int tagLen = aeCipher.AuthTagSizeBytes;
            Assert.True(encrypted.Length >= nonceLen + tagLen);
            
            byte[] nonce = new byte[nonceLen];
            byte[] tag = new byte[tagLen];
            byte[] ciphertext = new byte[encrypted.Length - nonceLen - tagLen];

            Buffer.BlockCopy(encrypted, 0, nonce, 0, nonceLen);
            Buffer.BlockCopy(encrypted, nonceLen, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(encrypted, nonceLen + ciphertext.Length, tag, 0, tagLen);

            if (nonceLen > 0)
            {
                Assert.NotEmpty(nonce);
            }
            Assert.NotEmpty(tag);
        }
        else
        {
            Assert.True(encrypted.Length >= nonceLen);
            
            byte[] nonce = new byte[nonceLen];
            byte[] ciphertext = new byte[encrypted.Length - nonceLen];

            Buffer.BlockCopy(encrypted, 0, nonce, 0, nonceLen);
            Buffer.BlockCopy(encrypted, nonceLen, ciphertext, 0, ciphertext.Length);

            if (nonceLen > 0)
            {
                Assert.NotEmpty(nonce);
            }
        }
    }

    [Fact]
    public void EncryptDecrypt_Roundtrip()
    {
        var key = GenerateKey();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.Encrypt(key, plaintext);
        var decrypted = Cipher.Decrypt(key, encrypted);

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

        var encrypted = Cipher.Encrypt(key, plaintext);
        Assert.NotNull(encrypted);

        var decrypted = Cipher.Decrypt(key, encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64_Succeeds()
    {
        var key = Cipher.GenerateKeyBase64();
        var plaintext = "hello world";

        var encrypted = Cipher.EncryptBase64(key, plaintext);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var decrypted = Cipher.DecryptBase64(key, encrypted);
        Assert.False(string.IsNullOrEmpty(decrypted));
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64Mixed_Succeeds()
    {
        string keyString = Cipher.GenerateKeyBase64();
        byte[] plaintextBytes = Encoding.UTF8.GetBytes("hello world");

        var encrypted = Cipher.Encrypt(keyString, plaintextBytes);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var decrypted = Cipher.Decrypt(keyString, encrypted);
        Assert.NotNull(decrypted);
        Assert.NotEmpty(decrypted);
        Assert.Equal(plaintextBytes, decrypted);
    }

    [Fact]
    public void Encrypt_WithNonce_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("nonce test");
        var nonce = Cipher.GenerateNonce();

        var encrypted = Cipher.Encrypt(key, plaintext, nonce);

        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKey_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key: [], plaintext));
    }

    [Fact]
    public void Encrypt_WithInvalidNullPlaintext_Throws()
    {
        var key = Cipher.GenerateKey();
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key, plaintext: null!));
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyNonce_Throws()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key, plaintext, nonce: []));
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKeyAndPlaintext_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key: [], plaintext: []));
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKeyAndPlaintextAndNonce_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key: [], plaintext: [], nonce: []));
    }

    [Fact]
    public void Encrypt_WithInvalidNullKey_Throws()
    {
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key: null!, plaintext));
    }



    [Fact]
    public void Encrypt_WithInvalidNullNonce_Throws()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key, plaintext, nonce: null!));
    }

    [Fact]
    public void Encrypt_WithInvalidNullKeyAndPlaintext_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key: null!, plaintext: null!));
    }

    [Fact]
    public void Encrypt_WithInvalidNullKeyAndPlaintextAndNonce_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(key: null!, plaintext: null!, nonce: null!));
    }

    [Fact]
    public void SymmetricCipherExtensions_NullHandling()
    {
        ISymmetricCipher? nullSymmetric = null;

        Assert.False(nullSymmetric!.TryEncrypt([1, 2], [3, 4], out _));
        Assert.False(nullSymmetric!.TryEncryptBase64("key", "plain", out _));
        Assert.False(nullSymmetric!.TryDecryptBase64("key", "enc", out _));

        Assert.Throws<ArgumentNullException>(() => nullSymmetric!.GenerateKey());
        Assert.Throws<ArgumentNullException>(() => nullSymmetric!.GenerateNonce());
        Assert.Throws<ArgumentNullException>(() => nullSymmetric!.GenerateNonceBase64());
        Assert.Throws<ArgumentNullException>(() => nullSymmetric!.GenerateKeyBase64());
    }
}

