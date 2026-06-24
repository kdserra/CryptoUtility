using System;
using System.Text;
using Xunit;

namespace CryptoUtility.Tests;

public class KeyEncapsulationMechanismExtensionsTests
{
    private readonly IKeyEncapsulationMechanism _kem = CryptoUtility.BouncyCastle.MlKem768Impl.Shared;
    private readonly ISymmetricCipher _symmetricCipher = CryptoUtility.System.Aes256Gcm.Shared;
    private readonly IKeyExpansionKdf _kdf = CryptoUtility.System.Hkdf.Shared;

    [Fact]
    public void Kem_EncryptDecrypt_Roundtrip_Succeeds()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();
        var plaintext = Encoding.UTF8.GetBytes("Post-quantum encryption test payload.");
        var salt = Encoding.UTF8.GetBytes("KdfSalt-12345");
        var info = Encoding.UTF8.GetBytes("KdfInfo-67890");

        var encrypted = _kem.Encrypt(
            _symmetricCipher,
            _kdf,
            publicKey,
            plaintext,
            salt,
            info
        );

        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var decrypted = _kem.Decrypt(
            _symmetricCipher,
            _kdf,
            secretKey,
            encrypted,
            salt,
            info
        );

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Kem_EncryptDecryptBase64_Roundtrip_Succeeds()
    {
        var (publicKeyBase64, secretKeyBase64) = KeyEncapsulationMechanismExtensions.GenerateKeyPair(_kem);
        var plaintext = "Base64 post-quantum encryption test.";
        var saltBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("KdfSalt-Base64"));
        var infoBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("KdfInfo-Base64"));

        var encryptedBase64 = _kem.EncryptBase64(
            _symmetricCipher,
            _kdf,
            publicKeyBase64,
            plaintext,
            saltBase64,
            infoBase64
        );

        Assert.False(string.IsNullOrEmpty(encryptedBase64));

        var decrypted = _kem.DecryptBase64(
            _symmetricCipher,
            _kdf,
            secretKeyBase64,
            encryptedBase64,
            saltBase64,
            infoBase64
        );

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Kem_TryEncryptDecrypt_Roundtrip_Succeeds()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();
        var plaintext = Encoding.UTF8.GetBytes("Try-pattern post-quantum encryption payload.");
        var salt = Encoding.UTF8.GetBytes("KdfSalt-Try");
        var info = Encoding.UTF8.GetBytes("KdfInfo-Try");

        var encSuccess = _kem.TryEncrypt(
            _symmetricCipher,
            _kdf,
            publicKey,
            plaintext,
            salt,
            info,
            out var encrypted
        );

        Assert.True(encSuccess);
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);

        var decSuccess = _kem.TryDecrypt(
            _symmetricCipher,
            _kdf,
            secretKey,
            encrypted,
            salt,
            info,
            out var decrypted
        );

        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Kem_TryEncryptDecryptBase64_Roundtrip_Succeeds()
    {
        var (publicKeyBase64, secretKeyBase64) = KeyEncapsulationMechanismExtensions.GenerateKeyPair(_kem);
        var plaintext = "Try-pattern Base64 post-quantum encryption payload.";
        var saltBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("KdfSalt-Try-Base64"));
        var infoBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("KdfInfo-Try-Base64"));

        var encSuccess = _kem.TryEncryptBase64(
            _symmetricCipher,
            _kdf,
            publicKeyBase64,
            plaintext,
            saltBase64,
            infoBase64,
            out var encryptedBase64
        );

        Assert.True(encSuccess);
        Assert.False(string.IsNullOrEmpty(encryptedBase64));

        var decSuccess = _kem.TryDecryptBase64(
            _symmetricCipher,
            _kdf,
            secretKeyBase64,
            encryptedBase64,
            saltBase64,
            infoBase64,
            out var decrypted
        );

        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Kem_Decrypt_CorruptedEnvelope_Throws()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();
        var plaintext = Encoding.UTF8.GetBytes("Some payload.");
        var salt = Encoding.UTF8.GetBytes("Salt");
        var info = Encoding.UTF8.GetBytes("Info");

        var encrypted = _kem.Encrypt(
            _symmetricCipher,
            _kdf,
            publicKey,
            plaintext,
            salt,
            info
        );

        // Corrupt the envelope bytes
        byte[] corrupted = new byte[encrypted.Length];
        Array.Copy(encrypted, corrupted, encrypted.Length);
        for (int i = 0; i < 8 && i < corrupted.Length; i++)
        {
            corrupted[i] ^= 0xFF; // Invert envelope header
        }

        Assert.ThrowsAny<Exception>(() => _kem.Decrypt(
            _symmetricCipher,
            _kdf,
            secretKey,
            corrupted,
            salt,
            info
        ));
    }

    [Fact]
    public void Kem_TryDecrypt_CorruptedEnvelope_ReturnsFalse()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();
        var plaintext = Encoding.UTF8.GetBytes("Some payload.");
        var salt = Encoding.UTF8.GetBytes("Salt");
        var info = Encoding.UTF8.GetBytes("Info");

        var encrypted = _kem.Encrypt(
            _symmetricCipher,
            _kdf,
            publicKey,
            plaintext,
            salt,
            info
        );

        byte[] corrupted = new byte[encrypted.Length];
        Array.Copy(encrypted, corrupted, encrypted.Length);
        if (corrupted.Length > 0)
        {
            corrupted[corrupted.Length - 1] ^= 0xFF; // Corrupt ciphertext
        }

        var decSuccess = _kem.TryDecrypt(
            _symmetricCipher,
            _kdf,
            secretKey,
            corrupted,
            salt,
            info,
            out var decrypted
        );

        Assert.False(decSuccess);
        Assert.Empty(decrypted);
    }
}
