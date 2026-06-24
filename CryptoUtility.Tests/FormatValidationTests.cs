using System;
using System.Buffers.Binary;
using System.Text;
using CryptoUtility.BouncyCastle;
using CryptoUtility.System;
using CryptoUtility.System.Extras;
using Xunit;

namespace CryptoUtility.Tests;

public class FormatValidationTests
{
    [Fact]
    public void ValidateAeadCipherFormat_Aes256Gcm()
    {
        // AEAD layout: [Nonce][Ciphertext][Auth Tag]
        var cipher = CryptoUtility.System.Aes256GcmImpl.Shared;
        byte[] key = cipher.GenerateKey();
        byte[] nonce = cipher.GenerateNonce();
        byte[] plaintext = "Hello"u8.ToArray();

        byte[] encrypted = cipher.Encrypt(key, plaintext, nonce);

        int expectedLength = nonce.Length + plaintext.Length + cipher.AuthTagSizeBytes;
        Assert.Equal(expectedLength, encrypted.Length);

        // Verify nonce prefix matches the nonce we passed
        byte[] extractedNonce = new byte[nonce.Length];
        Buffer.BlockCopy(encrypted, 0, extractedNonce, 0, nonce.Length);
        Assert.Equal(nonce, extractedNonce);
    }

    [Fact]
    public void ValidateHybridEnvelopeFormat_Rsa2048()
    {
        // Hybrid layout: | AsymEncrypted Length (4 bytes) | AsymEncrypted Payload | SymEncrypted Payload |
        var asymmetric = CryptoUtility.System.Rsa2048Impl.Shared;
        var symmetric = CryptoUtility.System.Aes256GcmImpl.Shared;
        var (pubKey, secKey) = asymmetric.GenerateKeyPair();
        byte[] plaintext = "Secret Message"u8.ToArray();

        byte[] encrypted = asymmetric.HybridEncrypt(symmetric, pubKey, plaintext);

        Assert.True(encrypted.Length > 4);

        int asymLength = BinaryPrimitives.ReadInt32BigEndian(encrypted.AsSpan(0, 4));

        Assert.True(asymLength > 0);
        Assert.Equal(encrypted.Length, 4 + asymLength + (symmetric.NonceSizeBytes + plaintext.Length + symmetric.AuthTagSizeBytes));
    }

    [Fact]
    public void ValidatePasswordHashingPhcFormats()
    {
        // PBKDF2 format check
        var pbkdf2 = CryptoUtility.System.Pbkdf2Impl.Shared;
        string pbkdf2Hash = pbkdf2.HashPassword("password123");
        Assert.StartsWith("$pbkdf2-sha256$", pbkdf2Hash);

        // Bcrypt format check
        var bcrypt = CryptoUtility.BouncyCastle.BcryptImpl.Shared;
        string bcryptHash = bcrypt.HashPassword("password123");
        Assert.StartsWith("$2", bcryptHash); // Bcrypt typically starts with $2a$, $2y$, or $2b$

        // Scrypt format check
        var scrypt = CryptoUtility.BouncyCastle.ScryptImpl.Shared;
        string scryptHash = scrypt.HashPassword("password123");
        Assert.StartsWith("$scrypt$", scryptHash);

        // Argon2id format check
        var argon2id = CryptoUtility.BouncyCastle.Argon2idImpl.Shared;
        string argon2Hash = argon2id.HashPassword("password123");
        Assert.StartsWith("$argon2id$", argon2Hash);
    }
}
