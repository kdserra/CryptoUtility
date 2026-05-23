using System.Text;

namespace CryptoUtility.Tests;

public abstract class AsymmetricCipherTests
{
    public abstract IAsymmetricCipher Cipher { get; }

    protected (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        return Cipher.GenerateKeyPair();
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
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okEnc, encrypted) = Cipher.EncryptBase64(pub, message);
        Assert.True(okEnc);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var (okDec, decrypted) = Cipher.DecryptBase64(sec, encrypted);
        Assert.True(okDec);
        Assert.Equal(message, decrypted);
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
    public void HybridEncryptDecrypt_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.HybridEncrypt(pub, plaintext);
        Assert.True(okEnc);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var (okDec, decrypted) = Cipher.HybridDecrypt(sec, encrypted);
        Assert.True(okDec);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void HybridEncryptDecrypt_Base64_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okEnc, encrypted) = Cipher.HybridEncryptBase64(pub, message);
        Assert.True(okEnc);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var (okDec, decrypted) = Cipher.HybridDecryptBase64(sec, encrypted);
        Assert.True(okDec);
        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void HybridDecrypt_ModifiedCiphertext_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.HybridEncrypt(pub, plaintext);
        Assert.True(okEnc);

        encrypted[0] ^= 0xFF;

        var (okDec, decrypted) = Cipher.HybridDecrypt(sec, encrypted);
        Assert.False(okDec);
        Assert.Empty(decrypted);
    }

    [Fact]
    public void HybridDecrypt_WrongKey_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var (pub2, sec2) = GenerateKeyPair();

        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.HybridEncrypt(pub, plaintext);
        Assert.True(okEnc);

        var (okDec, decrypted) = Cipher.HybridDecrypt(sec2, encrypted);
        Assert.False(okDec);
        Assert.Empty(decrypted);
    }

    [Fact]
    public void HybridDecrypt_WrongCipher_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.HybridEncrypt(pub, plaintext, ChaCha20Poly1305Impl.Shared);
        Assert.True(okEnc);

        var (okDec, decrypted) = Cipher.HybridDecrypt(sec, encrypted, Aes256GcmImpl.Shared);
        Assert.False(okDec);
        Assert.Empty(decrypted);
    }


    [Fact]
    public void HybridEncrypt_WithEmptyInputs_Fails()
    {
        var plaintext = GeneratePlaintext();

        var (success1, enc1) = Cipher.HybridEncrypt([], plaintext);
        Assert.False(success1);
        Assert.Empty(enc1);

        var (pub, _) = GenerateKeyPair();

        var (success2, enc2) = Cipher.HybridEncrypt(pub, []);
        Assert.False(success2);
        Assert.Empty(enc2);
    }

    [Fact]
    public void HybridDecrypt_WithEmptyInputs_Fails()
    {
        var (_, sec) = GenerateKeyPair();

        var (success1, pt1) = Cipher.HybridDecrypt([], new byte[] { 1 });
        Assert.False(success1);
        Assert.Empty(pt1);

        var (success2, pt2) = Cipher.HybridDecrypt(sec, []);
        Assert.False(success2);
        Assert.Empty(pt2);
    }

    [Fact]
    public void HybridEncrypt_WithNullInputs_Fails()
    {
        var plaintext = GeneratePlaintext();

        var (success, encrypted) = Cipher.HybridEncrypt(null!, plaintext);
        Assert.False(success);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void HybridDecrypt_WithNullInputs_Fails()
    {
        var (success, plaintext) = Cipher.HybridDecrypt(null!, new byte[] { 1 });
        Assert.False(success);
        Assert.Empty(plaintext);
    }

    [Fact]
    public void HybridDecrypt_InvalidEnvelope_Fails()
    {
        var (_, sec) = GenerateKeyPair();

        var garbage = new byte[] { 1, 2, 3, 4, 5 };

        var (success, plaintext) = Cipher.HybridDecrypt(sec, garbage);
        Assert.False(success);
        Assert.Empty(plaintext);
    }

    [Fact]
    public void HybridDecryptBase64_ModifiedCiphertext_Fails()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okEnc, encrypted) = Cipher.HybridEncryptBase64(pub, message);
        Assert.True(okEnc);

        var bytes = Convert.FromBase64String(encrypted);
        bytes[0] ^= 0xFF;
        var tampered = Convert.ToBase64String(bytes);

        var (okDec, decrypted) = Cipher.HybridDecryptBase64(sec, tampered);
        Assert.False(okDec);
        Assert.True(string.IsNullOrEmpty(decrypted));
    }

    [Fact]
    public void HybridDecryptBase64_InvalidInputs_Fails()
    {
        var result = Cipher.HybridDecryptBase64("", "");
        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.plaintext));
    }

    [Fact]
    public void HybridDecryptBase64_NullInputs_Fails()
    {
        var result = Cipher.HybridDecryptBase64(null!, null!);
        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.plaintext));
    }

    [Fact]
    public void HybridEncryptDecrypt_ChaCha20Poly1305_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var plaintext = GeneratePlaintext();

        var (okEnc, encrypted) = Cipher.HybridEncrypt(pub, plaintext, ChaCha20Poly1305Impl.Shared);
        Assert.True(okEnc);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var (okDec, decrypted) = Cipher.HybridDecrypt(sec, encrypted, ChaCha20Poly1305Impl.Shared);
        Assert.True(okDec);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void HybridEncryptDecryptBase64_ChaCha20Poly1305_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okEnc, encrypted) = Cipher.HybridEncryptBase64(pub, message, ChaCha20Poly1305Impl.Shared);
        Assert.True(okEnc);
        Assert.False(string.IsNullOrEmpty(encrypted));

        var (okDec, decrypted) = Cipher.HybridDecryptBase64(sec, encrypted, ChaCha20Poly1305Impl.Shared);
        Assert.True(okDec);
        Assert.Equal(message, decrypted);
    }


    [Fact]
    public void AsymmetricCipherExtensions_NullHandling()
    {
        IAsymmetricCipher? nullCipher = null;
        ISymmetricCipher? mockSymmetric = Aes256GcmImpl.Shared;

        var (encSuccess, encResult) = nullCipher!.EncryptBase64("publicKey", "plaintext");
        Assert.False(encSuccess);
        Assert.Equal(string.Empty, encResult);

        var (decSuccess, decResult) = nullCipher!.DecryptBase64("secretKey", "encrypted");
        Assert.False(decSuccess);
        Assert.Equal(string.Empty, decResult);

        var (pub, sec) = nullCipher!.GenerateKeyPairBase64();
        Assert.Equal(string.Empty, pub);
        Assert.Equal(string.Empty, sec);

        var (h1Success, h1Encrypted) = nullCipher!.HybridEncrypt(mockSymmetric, [1, 2], [3, 4]);
        Assert.False(h1Success);
        Assert.Empty(h1Encrypted);

        var (h1DecSuccess, h1Plaintext) = nullCipher!.HybridDecrypt(mockSymmetric, [1, 2], [3, 4]);
        Assert.False(h1DecSuccess);
        Assert.Empty(h1Plaintext);

        var (h2Success, h2Encrypted) = nullCipher!.HybridEncrypt([1, 2], [3, 4]);
        Assert.False(h2Success);
        Assert.Empty(h2Encrypted);

        var (h2DecSuccess, h2Plaintext) = nullCipher!.HybridDecrypt([1, 2], [3, 4]);
        Assert.False(h2DecSuccess);
        Assert.Empty(h2Plaintext);

        var (h3Success, h3Encrypted) = nullCipher!.HybridEncryptBase64("pubKey", "plain");
        Assert.False(h3Success);
        Assert.Equal(string.Empty, h3Encrypted);

        var (h3DecSuccess, h3Plaintext) = nullCipher!.HybridDecryptBase64("secKey", "enc");
        Assert.False(h3DecSuccess);
        Assert.Equal(string.Empty, h3Plaintext);
    }
}

