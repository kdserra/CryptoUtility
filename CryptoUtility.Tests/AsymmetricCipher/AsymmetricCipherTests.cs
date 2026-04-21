using System.Text;

namespace CryptoUtility.Tests;

public abstract class AsymmetricCipherTests
{
    internal abstract AsymmetricCipher Cipher { get; }

    protected (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        return Cipher.GenerateKey();
    }

    protected byte[] GeneratePlaintext()
    {
        return Encoding.UTF8.GetBytes("Hello, world!");
    }

    [Fact]
    public void GenerateKey_HasCorrectLengths()
    {
        var (pub, sec) = GenerateKeyPair();

        Assert.NotNull(pub);
        Assert.NotNull(sec);
        Assert.NotEmpty(pub);
        Assert.NotEmpty(sec);
        Assert.True(pub.Length >= Cipher.KeySizeBytes);
        Assert.True(sec.Length >= Cipher.KeySizeBytes);
    }

    [Fact]
    public void EncryptDecrypt_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.Encrypt(pub, plaintext);
        Assert.True(okEnc);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var (okDec, decrypted) = Cipher.Decrypt(sec, encrypted);
        Assert.True(okDec);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyBase64();
        string message = "hello world";

        var (okEnc, encrypted) = Cipher.EncryptBase64(pub, message);
        Assert.True(okEnc);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var (okDec, decrypted) = Cipher.DecryptBase64(sec, encrypted);
        Assert.True(okDec);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void SignVerify_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        var (okSign, signature) = Cipher.Sign(message, sec);
        Assert.True(okSign);
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);

        var verified = Cipher.Verify(message, signature, pub);
        Assert.True(verified);
    }

    [Fact]
    public void Verify_ModifiedMessage_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        var (okSign, signature) = Cipher.Sign(message, sec);
        Assert.True(okSign);

        var tampered = Encoding.UTF8.GetBytes("tampered");

        var verified = Cipher.Verify(tampered, signature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void Verify_ModifiedSignature_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        var (okSign, signature) = Cipher.Sign(message, sec);
        Assert.True(okSign);

        signature[0] ^= 0xFF; // flip a bit

        var verified = Cipher.Verify(message, signature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKey_Fails()
    {
        var plaintext = GeneratePlaintext();

        var (success, encrypted) = Cipher.Encrypt([], plaintext);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyPlaintext_Fails()
    {
        var (pub, _) = GenerateKeyPair();

        var (success, encrypted) = Cipher.Encrypt(pub, []);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Decrypt_WithInvalidEmptyKey_Fails()
    {
        var (_, sec) = GenerateKeyPair();

        var (success, plaintext) = Cipher.Decrypt([], new byte[] { 1, 2, 3 });

        Assert.False(success);
        Assert.NotNull(plaintext);
        Assert.Empty(plaintext);
    }

    [Fact]
    public void Decrypt_WithInvalidEmptyCiphertext_Fails()
    {
        var (_, sec) = GenerateKeyPair();

        var (success, plaintext) = Cipher.Decrypt(sec, []);

        Assert.False(success);
        Assert.NotNull(plaintext);
        Assert.Empty(plaintext);
    }

    [Fact]
    public void Sign_WithInvalidEmptyKey_Fails()
    {
        var message = GeneratePlaintext();

        var (success, signature) = Cipher.Sign(message, []);

        Assert.False(success);
        Assert.NotNull(signature);
        Assert.Empty(signature);
    }

    [Fact]
    public void Sign_WithInvalidEmptyMessage_Fails()
    {
        var (_, sec) = GenerateKeyPair();

        var (success, signature) = Cipher.Sign([], sec);

        Assert.False(success);
        Assert.NotNull(signature);
        Assert.Empty(signature);
    }

    [Fact]
    public void Verify_WithInvalidInputs_Fails()
    {
        var result = Cipher.Verify([], [], []);
        Assert.False(result);
    }

    [Fact]
    public void Encrypt_WithNullKey_Fails()
    {
        var plaintext = GeneratePlaintext();

        var (success, encrypted) = Cipher.Encrypt(null!, plaintext);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Decrypt_WithNullKey_Fails()
    {
        var (success, plaintext) = Cipher.Decrypt(null!, new byte[] { 1 });

        Assert.False(success);
        Assert.NotNull(plaintext);
        Assert.Empty(plaintext);
    }

    [Fact]
    public void Sign_WithNullKey_Fails()
    {
        var message = GeneratePlaintext();

        var (success, signature) = Cipher.Sign(message, null!);

        Assert.False(success);
        Assert.NotNull(signature);
        Assert.Empty(signature);
    }

    [Fact]
    public void Verify_WithNullInputs_Fails()
    {
        var result = Cipher.Verify(null!, null!, null!);
        Assert.False(result);
    }
}
