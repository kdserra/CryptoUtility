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
        Assert.Equal(
            encrypted.Length,
            4
                + asymLength
                + (symmetric.NonceSizeBytes + plaintext.Length + symmetric.AuthTagSizeBytes)
        );
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

    [Fact]
    public void ValidatePasswordHashingPhcBase64Compatibility()
    {
        IPasswordHasher[] hashers = [
            CryptoUtility.System.Pbkdf2Impl.Shared,
            CryptoUtility.BouncyCastle.Pbkdf2Impl.Shared,
            CryptoUtility.BouncyCastle.ScryptImpl.Shared,
            CryptoUtility.BouncyCastle.Argon2idImpl.Shared,
            CryptoUtility.BouncyCastle.Argon2iImpl.Shared,
            CryptoUtility.BouncyCastle.Argon2dImpl.Shared
        ];

        string password = "PHC_Compatibility_Test_123!@#";

        foreach (var hasher in hashers)
        {
            string hash = hasher.HashPassword(password);
            var parts = hash.Split('$');
            
            Assert.True(parts.Length >= 4, $"Hash for {hasher.GetType().Name} has too few parts: {hash}");
            
            string saltB64 = parts[parts.Length - 2];
            string hashB64 = parts[parts.Length - 1];

            // 1. Validate that standard base64 characters '+' and '=' are not present
            Assert.DoesNotContain("+", saltB64);
            Assert.DoesNotContain("=", saltB64);
            Assert.DoesNotContain("+", hashB64);
            Assert.DoesNotContain("=", hashB64);

            // 2. Validate that the alphabet consists only of Argon2 B64 characters: ./0-9A-Za-z
            foreach (char c in saltB64)
            {
                Assert.True(
                    c == '.' || c == '/' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'),
                    $"Invalid character '{c}' in salt: {saltB64}"
                );
            }
            foreach (char c in hashB64)
            {
                Assert.True(
                    c == '.' || c == '/' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'),
                    $"Invalid character '{c}' in checksum: {hashB64}"
                );
            }

            // 3. Verify decoding works correctly using PhcB64
            byte[] saltBytes = PhcB64.FromB64String(saltB64);
            byte[] hashBytes = PhcB64.FromB64String(hashB64);
            Assert.NotEmpty(saltBytes);
            Assert.NotEmpty(hashBytes);

            // 4. Verify password verification round-trip succeeds
            bool matches = hasher.VerifyPassword(password, hash);
            Assert.True(matches, $"Password verification failed for {hasher.GetType().Name}");
        }
    }
}
