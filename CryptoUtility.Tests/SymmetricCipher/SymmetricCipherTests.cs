using System.Text;

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

        var (okEnc, encrypted) = Cipher.Encrypt(key, plaintext);
        Assert.True(okEnc);

        var envelope = SymmetricCipherEnvelope.FromBytes(encrypted);

        Assert.NotNull(envelope);
        Assert.Equal(SymmetricCipherEnvelope.LatestVersion, envelope.Version);

        Assert.NotNull(envelope.Ciphertext);
        Assert.NotEmpty(envelope.Ciphertext);

        Assert.NotNull(envelope.Nonce);
        Assert.NotEmpty(envelope.Nonce);

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
        Assert.False(string.IsNullOrEmpty(decrypted));
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Base64Mixed_Succeeds()
    {
        string keyString = Cipher.GenerateKeyBase64();
        byte[] plaintextBytes = Encoding.UTF8.GetBytes("hello world");

        var (encSuccess, encrypted) = Cipher.EncryptBase64(keyString, plaintextBytes);
        Assert.True(encSuccess);
        Assert.False(encrypted.IsNullOrEmpty());

        var (decSuccess, decrypted) = Cipher.DecryptBase64(keyString, encrypted);
        Assert.True(decSuccess);
        Assert.False(decrypted.IsNullOrEmpty());
        Assert.Equal(plaintextBytes, decrypted);
    }

    [Fact]
    public void Encrypt_WithNonce_Succeeds()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("nonce test");
        var nonce = Cipher.GenerateNonce();

        var (success, encrypted) = Cipher.Encrypt(key, plaintext, nonce);

        Assert.True(success);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKey_Fails()
    {
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");

        var (success, encrypted) = Cipher.Encrypt(key: [], plaintext);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyPlaintext_Fails()
    {
        var key = Cipher.GenerateKey();

        var (success, encrypted) = Cipher.Encrypt(key, plaintext: []);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyNonce_Fails()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");

        var (success, encrypted) = Cipher.Encrypt(key, plaintext, nonce: []);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKeyAndPlaintext_Fails()
    {
        var (success, encrypted) = Cipher.Encrypt(key: [], plaintext: []);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidEmptyKeyAndPlaintextAndNonce_Fails()
    {
        var (success, encrypted) = Cipher.Encrypt(key: [], plaintext: [], nonce: []);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidNullKey_Fails()
    {
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");

        var (success, encrypted) = Cipher.Encrypt(key: null!, plaintext);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidNullPlaintext_Fails()
    {
        var key = Cipher.GenerateKey();

        var (success, encrypted) = Cipher.Encrypt(key, plaintext: null!);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidNullNonce_Fails()
    {
        var key = Cipher.GenerateKey();
        var plaintext = Encoding.UTF8.GetBytes("Hello, world!");

        var (success, encrypted) = Cipher.Encrypt(key, plaintext, nonce: null!);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidNullKeyAndPlaintext_Fails()
    {
        var (success, encrypted) = Cipher.Encrypt(key: null!, plaintext: null!);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidNullKeyAndPlaintextAndNonce_Fails()
    {
        var (success, encrypted) = Cipher.Encrypt(key: null!, plaintext: null!, nonce: null!);

        Assert.False(success);
        Assert.NotNull(encrypted);
        Assert.Empty(encrypted);
    }

    [Fact]
    public void GetThisCipher_ReturnsNotNull()
    {
        ISymmetricCipher? cipher = LibraryHelper.GetSymmetricCipherFromID(Cipher.CipherID);
        Assert.NotNull(cipher);
    }

    [Fact]
    public void GetAllCiphers_ReturnsNotNull()
    {
        foreach (SymmetricCipherID cipherID in Enum.GetValues(typeof(SymmetricCipherID)))
        {
            if (cipherID == SymmetricCipherID.None)
            {
                continue;
            }

            ISymmetricCipher? cipher = LibraryHelper.GetSymmetricCipherFromID(cipherID);
            Assert.NotNull(cipher);
        }
    }

    [Fact]
    public void GetAllCiphers_NotNullAndMatchesExpected()
    {
        foreach (SymmetricCipherID cipherID in Enum.GetValues(typeof(SymmetricCipherID)))
        {
            if (cipherID == SymmetricCipherID.None)
            {
                continue;
            }

            ISymmetricCipher? cipher = LibraryHelper.GetSymmetricCipherFromID(cipherID);
            Assert.NotNull(cipher);

            string cipherTypeName = cipher?.GetType().Name ?? "null";
            string cipherIDName = cipherID.ToString();

            foreach (string suffix in Helper.ImplementationSuffixes)
            {
                cipherIDName = cipherIDName.Replace(suffix, "");
            }

            Assert.Equal(cipherTypeName, cipherIDName + "Impl");
        }
    }
}
