using System.Text;
using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public abstract class AsymmetricCipherTests
{
    public abstract IAsymmetricCipher Cipher { get; }

    protected (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        return Cipher.GenerateKeyPair();
    }

    protected byte[] GeneratePlaintext()
    {
        return Encoding.UTF8.GetBytes("Hello, world!");
    }

    [Fact]
    public abstract void Verify_AlgorithmSpecification();

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
    public void GenerateKeyPair_Try_Succeeds()
    {
        bool success = Cipher.TryGenerateKeyPair(out var pub, out var sec);
        Assert.True(success);
        Assert.NotNull(pub);
        Assert.NotNull(sec);
        Assert.NotEmpty(pub);
        Assert.NotEmpty(sec);
    }

    [Fact]
    public void GenerateKeyPairBase64_Try_Succeeds()
    {
        bool success = Cipher.TryGenerateKeyPairBase64(out var pub, out var sec);
        Assert.True(success);
        Assert.False(string.IsNullOrEmpty(pub));
        Assert.False(string.IsNullOrEmpty(sec));
    }

    [Fact]
    public void EncryptDecrypt_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.Encrypt(pub, plaintext);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var decrypted = Cipher.Decrypt(sec, encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Try_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        bool encSuccess = Cipher.TryEncrypt(pub, plaintext, out var encrypted);
        Assert.True(encSuccess);
        Assert.NotNull(encrypted);

        bool decSuccess = Cipher.TryDecrypt(sec, encrypted, out var decrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var encrypted = Cipher.EncryptBase64(pub, message);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var decrypted = Cipher.DecryptBase64(sec, encrypted);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64_Try_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        bool encSuccess = Cipher.TryEncryptBase64(pub, message, out var encrypted);
        Assert.True(encSuccess);
        Assert.False(string.IsNullOrEmpty(encrypted));

        bool decSuccess = Cipher.TryDecryptBase64(sec, encrypted, out var decrypted);
        Assert.True(decSuccess);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKey_ThrowsOrFails()
    {
        var plaintext = GeneratePlaintext();
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt([], plaintext));
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKey_Try_ReturnsFalse()
    {
        var plaintext = GeneratePlaintext();
        bool success = Cipher.TryEncrypt([], plaintext, out _);
        Assert.False(success);
    }

    [Fact]
    public void Encrypt_WithInvalidNullPlaintext_ThrowsOrFails()
    {
        var (pub, _) = GenerateKeyPair();
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(pub, null!));
    }

    [Fact]
    public void Encrypt_WithNullKey_ThrowsOrFails()
    {
        var plaintext = GeneratePlaintext();
        Assert.ThrowsAny<Exception>(() => Cipher.Encrypt(null!, plaintext));
    }

    [Fact]
    public void Decrypt_WithNullKey_ThrowsOrFails()
    {
        Assert.ThrowsAny<Exception>(() => Cipher.Decrypt(null!, new byte[] { 1 }));
    }

    [Fact]
    public void HybridEncryptDecrypt_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.HybridEncrypt(Aes256Gcm.Shared, pub, plaintext);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var decrypted = Cipher.HybridDecrypt(Aes256Gcm.Shared, sec, encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void HybridEncryptDecrypt_Try_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        bool encSuccess = Cipher.TryHybridEncrypt(Aes256Gcm.Shared, pub, plaintext, out var encrypted);
        Assert.True(encSuccess);
        Assert.NotNull(encrypted);

        bool decSuccess = Cipher.TryHybridDecrypt(Aes256Gcm.Shared, sec, encrypted, out var decrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void HybridEncryptDecrypt_Base64_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var encrypted = Cipher.HybridEncryptBase64(Aes256Gcm.Shared, pub, message);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var decrypted = Cipher.HybridDecryptBase64(Aes256Gcm.Shared, sec, encrypted);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void HybridEncryptDecrypt_Base64_Try_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        bool encSuccess = Cipher.TryHybridEncryptBase64(Aes256Gcm.Shared, pub, message, out var encrypted);
        Assert.True(encSuccess);

        bool decSuccess = Cipher.TryHybridDecryptBase64(Aes256Gcm.Shared, sec, encrypted, out var decrypted);
        Assert.True(decSuccess);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void HybridDecrypt_ModifiedCiphertext_ThrowsOrFails()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.HybridEncrypt(Aes256Gcm.Shared, pub, plaintext);
        encrypted[0] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => Cipher.HybridDecrypt(Aes256Gcm.Shared, sec, encrypted));
    }

    [Fact]
    public void HybridDecrypt_ModifiedCiphertext_Try_ReturnsFalse()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        bool encSuccess = Cipher.TryHybridEncrypt(Aes256Gcm.Shared, pub, plaintext, out var encrypted);
        Assert.True(encSuccess);
        encrypted[0] ^= 0xFF;

        bool decSuccess = Cipher.TryHybridDecrypt(Aes256Gcm.Shared, sec, encrypted, out _);
        Assert.False(decSuccess);
    }

    [Fact]
    public void HybridDecrypt_WrongKey_ThrowsOrFails()
    {
        var (pub, sec) = GenerateKeyPair();
        var (pub2, sec2) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.HybridEncrypt(Aes256Gcm.Shared, pub, plaintext);

        Assert.ThrowsAny<Exception>(() => Cipher.HybridDecrypt(Aes256Gcm.Shared, sec2, encrypted));
    }

    [Fact]
    public void HybridDecrypt_WrongCipher_ThrowsOrFails()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.HybridEncrypt(ChaCha20Poly1305.Shared, pub, plaintext);

        Assert.ThrowsAny<Exception>(() => Cipher.HybridDecrypt(Aes256Gcm.Shared, sec, encrypted));
    }

    [Fact]
    public void HybridEncrypt_WithNullKey_ThrowsOrFails()
    {
        var plaintext = GeneratePlaintext();
        Assert.ThrowsAny<Exception>(() => Cipher.HybridEncrypt(Aes256Gcm.Shared, null!, plaintext));
    }

    [Fact]
    public void HybridDecrypt_WithNullKey_ThrowsOrFails()
    {
        Assert.ThrowsAny<Exception>(() => Cipher.HybridDecrypt(Aes256Gcm.Shared, null!, new byte[] { 1 }));
    }

    [Fact]
    public void HybridDecrypt_InvalidEnvelope_ThrowsOrFails()
    {
        var (_, sec) = GenerateKeyPair();
        var garbage = new byte[] { 1, 2, 3, 4, 5 };

        Assert.ThrowsAny<Exception>(() => Cipher.HybridDecrypt(Aes256Gcm.Shared, sec, garbage));
    }

    [Fact]
    public void AsymmetricCipherExtensions_NullHandling_Try_ReturnsFalse()
    {
        IAsymmetricCipher? nullCipher = null;
        ISymmetricCipher mockSymmetric = Aes256GcmImpl.Shared;

        Assert.False(nullCipher!.TryEncryptBase64("publicKey", "plaintext", out _));
        Assert.False(nullCipher!.TryDecryptBase64("secretKey", "encrypted", out _));
        Assert.False(nullCipher!.TryGenerateKeyPair(out _, out _));
        Assert.False(nullCipher!.TryGenerateKeyPairBase64(out _, out _));
        Assert.False(nullCipher!.TryHybridEncrypt(mockSymmetric, [1, 2], [3, 4], out _));
        Assert.False(nullCipher!.TryHybridDecrypt(mockSymmetric, [1, 2], [3, 4], out _));
        Assert.False(nullCipher!.TryHybridEncrypt(Aes256Gcm.Shared, [1, 2], [3, 4], out _));
        Assert.False(nullCipher!.TryHybridDecrypt(Aes256Gcm.Shared, [1, 2], [3, 4], out _));
        Assert.False(nullCipher!.TryHybridEncryptBase64(Aes256Gcm.Shared, "pubKey", "plain", out _));
        Assert.False(nullCipher!.TryHybridDecryptBase64(Aes256Gcm.Shared, "secKey", "enc", out _));
    }
}
