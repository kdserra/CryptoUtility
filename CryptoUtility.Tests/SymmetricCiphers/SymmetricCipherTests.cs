using System.Text;
using CryptoUtility;

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
    public void CipherId_IsValid()
    {
        Assert.NotEqual(CipherID.None, Cipher.CipherID);
    }

    [Fact]
    public void GenerateKey_HasCorrectLength()
    {
        var key = Cipher.GenerateKey();
        Assert.NotNull(key);
        Assert.Equal(Cipher.KeySizeBytes, key.Length);
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
}
