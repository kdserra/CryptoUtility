using System;
using System.Text;
using CryptoUtility.System;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class KeyAgreementTests
{
    internal abstract IKeyAgreement KeyAgreement { get; }

    internal abstract IKeyAgreement CreateNew();

    public abstract void Verify_AlgorithmSpecification();

    protected (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        return KeyAgreement.GenerateKeyPair();
    }

    protected byte[] GeneratePlaintext()
    {
        return Encoding.UTF8.GetBytes("Hello, world!");
    }

    [Fact]
    public void GenerateKeyPair_NotEmpty()
    {
        var (pub, sec) = GenerateKeyPair();

        Assert.NotNull(pub);
        Assert.NotNull(sec);
        Assert.NotEmpty(pub);
        Assert.NotEmpty(sec);
    }

    [Fact]
    public void KeyAgreement_SharedSecret_Roundtrip()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var secretA = a.DeriveSharedSecret(aSec, bPub);
        var secretB = b.DeriveSharedSecret(bSec, aPub);

        Assert.NotEmpty(secretA);
        Assert.NotEmpty(secretB);
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void DeriveSharedSecret_InvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecret([], []));
    }

    [Fact]
    public void DeriveSharedSecret_NullInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecret(null!, null!));
    }

    [Fact]
    public void GenerateKeyPairBase64_NotEmpty()
    {
        var (pub, sec) = KeyAgreement.GenerateKeyPairBase64();

        Assert.False(string.IsNullOrEmpty(pub));
        Assert.False(string.IsNullOrEmpty(sec));
    }

    [Fact]
    public void KeyAgreement_Base64_SharedSecret_Roundtrip()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPairBase64();
        var (bPub, bSec) = b.GenerateKeyPairBase64();

        var secretA = a.DeriveSharedSecretBase64(aSec, bPub);
        var secretB = b.DeriveSharedSecretBase64(bSec, aPub);

        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.False(string.IsNullOrEmpty(secretB));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void DeriveSharedSecretBase64_InvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecretBase64("", ""));
    }

    [Fact]
    public void DeriveSharedSecretBase64_NullInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecretBase64(null!, null!));
    }

    [Fact]
    public void SameInstance_SharedSecret_Roundtrip()
    {
        var a = KeyAgreement;
        var b = KeyAgreement;

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var secretA = a.DeriveSharedSecret(aSec, bPub);
        var secretB = b.DeriveSharedSecret(bSec, aPub);

        Assert.NotEmpty(secretA);
        Assert.NotEmpty(secretB);
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void SameInstance_DeriveSharedSecret_InvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecret([], []));
    }

    [Fact]
    public void SameInstance_DeriveSharedSecret_NullInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecret(null!, null!));
    }

    [Fact]
    public void SameInstance_Base64_SharedSecret_Roundtrip()
    {
        var a = KeyAgreement;
        var b = KeyAgreement;

        var (aPub, aSec) = a.GenerateKeyPairBase64();
        var (bPub, bSec) = b.GenerateKeyPairBase64();

        var secretA = a.DeriveSharedSecretBase64(aSec, bPub);
        var secretB = b.DeriveSharedSecretBase64(bSec, aPub);

        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.False(string.IsNullOrEmpty(secretB));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void SameInstance_DeriveSharedSecretBase64_InvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecretBase64("", ""));
    }

    [Fact]
    public void SameInstance_DeriveSharedSecretBase64_NullInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => KeyAgreement.DeriveSharedSecretBase64(null!, null!));
    }

    [Fact]
    public void NewInstance_SharedSecret_Roundtrip()
    {
        var a = CreateNew();
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var secretA = a.DeriveSharedSecret(aSec, bPub);
        var secretB = b.DeriveSharedSecret(bSec, aPub);

        Assert.NotEmpty(secretA);
        Assert.NotEmpty(secretB);
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void NewInstance_DeriveSharedSecret_InvalidInputs_Throws()
    {
        var a = CreateNew();
        Assert.ThrowsAny<Exception>(() => a.DeriveSharedSecret([], []));
    }

    [Fact]
    public void NewInstance_DeriveSharedSecret_NullInputs_Throws()
    {
        var a = CreateNew();
        Assert.ThrowsAny<Exception>(() => a.DeriveSharedSecret(null!, null!));
    }

    [Fact]
    public void NewInstance_Base64_SharedSecret_Roundtrip()
    {
        var a = CreateNew();
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPairBase64();
        var (bPub, bSec) = b.GenerateKeyPairBase64();

        var secretA = a.DeriveSharedSecretBase64(aSec, bPub);
        var secretB = b.DeriveSharedSecretBase64(bSec, aPub);

        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.False(string.IsNullOrEmpty(secretB));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void NewInstance_DeriveSharedSecretBase64_InvalidInputs_Throws()
    {
        var a = CreateNew();
        Assert.ThrowsAny<Exception>(() => a.DeriveSharedSecretBase64("", ""));
    }

    [Fact]
    public void NewInstance_DeriveSharedSecretBase64_NullInputs_Throws()
    {
        var a = CreateNew();
        Assert.ThrowsAny<Exception>(() => a.DeriveSharedSecretBase64(null!, null!));
    }

    [Fact]
    public void KeyAgreement_Base64_SharedSecret_Try_Roundtrip()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPairBase64();
        var (bPub, bSec) = b.GenerateKeyPairBase64();

        bool successA = a.TryDeriveSharedSecretBase64(aSec, bPub, out var secretA);
        bool successB = b.TryDeriveSharedSecretBase64(bSec, aPub, out var secretB);

        Assert.True(successA);
        Assert.True(successB);
        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void KeyAgreement_EncryptDecrypt_Roundtrip()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var secretA = a.DeriveSharedSecret(aSec, bPub);
        var secretB = b.DeriveSharedSecret(bSec, aPub);

        var plaintext = Encoding.UTF8.GetBytes("Super secret message");
        var salt = Encoding.UTF8.GetBytes("TestSalt");
        var info = Encoding.UTF8.GetBytes("ApplicationInfo");

        var ciphertext = a.Encrypt(Aes256Gcm.Shared, Hkdf.Shared, secretA, plaintext, salt, info);

        Assert.NotEmpty(ciphertext);

        var decrypted = b.Decrypt(Aes256Gcm.Shared, Hkdf.Shared, secretB, ciphertext, salt, info);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void KeyAgreement_EncryptDecrypt_Try_Roundtrip()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        bool deriveA = a.TryDeriveSharedSecret(aSec, bPub, out var secretA);
        bool deriveB = b.TryDeriveSharedSecret(bSec, aPub, out var secretB);
        Assert.True(deriveA);
        Assert.True(deriveB);

        var plaintext = Encoding.UTF8.GetBytes("Super secret message");
        var salt = Encoding.UTF8.GetBytes("TestSalt");
        var info = Encoding.UTF8.GetBytes("ApplicationInfo");

        bool encSuccess = a.TryEncrypt(
            Aes256Gcm.Shared,
            Hkdf.Shared,
            secretA,
            plaintext,
            salt,
            info,
            out var ciphertext
        );
        Assert.True(encSuccess);
        Assert.NotEmpty(ciphertext);

        bool decSuccess = b.TryDecrypt(
            Aes256Gcm.Shared,
            Hkdf.Shared,
            secretB,
            ciphertext,
            salt,
            info,
            out var decrypted
        );
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void KeyAgreement_EncryptDecrypt_WrongSecret_ThrowsOrFails()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var secretA = a.DeriveSharedSecret(aSec, bPub);

        var plaintext = Encoding.UTF8.GetBytes("Super secret message");
        var salt = Encoding.UTF8.GetBytes("TestSalt");
        var info = Encoding.UTF8.GetBytes("ApplicationInfo");

        var ciphertext = a.Encrypt(Aes256Gcm.Shared, Hkdf.Shared, secretA, plaintext, salt, info);

        // Derive wrong secret
        var wrongSec = b.DeriveSharedSecret(bSec, bPub);

        Assert.ThrowsAny<Exception>(() =>
            b.Decrypt(Aes256Gcm.Shared, Hkdf.Shared, wrongSec, ciphertext, salt, info)
        );
    }

    [Fact]
    public void KeyAgreement_EncryptDecrypt_WrongInfo_ThrowsOrFails()
    {
        var a = KeyAgreement;
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var secretA = a.DeriveSharedSecret(aSec, bPub);
        var secretB = b.DeriveSharedSecret(bSec, aPub);

        var plaintext = Encoding.UTF8.GetBytes("Super secret message");
        var salt = Encoding.UTF8.GetBytes("TestSalt");
        var info = Encoding.UTF8.GetBytes("ApplicationInfo");
        var wrongInfo = Encoding.UTF8.GetBytes("WrongApplicationInfo");

        var ciphertext = a.Encrypt(Aes256Gcm.Shared, Hkdf.Shared, secretA, plaintext, salt, info);

        Assert.ThrowsAny<Exception>(() =>
            b.Decrypt(Aes256Gcm.Shared, Hkdf.Shared, secretB, ciphertext, salt, wrongInfo)
        );
    }

    [Fact]
    public void KeyAgreementExtensions_NullHandling_Try_ReturnsFalse()
    {
        IKeyAgreement? nullAgreement = null;

        Assert.False(nullAgreement!.TryDeriveSharedSecretBase64("secKey", "pubKey", out _));
        Assert.False(nullAgreement!.TryGenerateKeyPair(out _, out _));
        Assert.False(nullAgreement!.TryGenerateKeyPairBase64(out _, out _));
        Assert.False(
            nullAgreement!.TryEncrypt(
                Aes256Gcm.Shared,
                Hkdf.Shared,
                [1, 2],
                [3, 4],
                [5, 6],
                [7, 8],
                out _
            )
        );
        Assert.False(
            nullAgreement!.TryDecrypt(
                Aes256Gcm.Shared,
                Hkdf.Shared,
                [1, 2],
                [3, 4],
                [5, 6],
                [7, 8],
                out _
            )
        );
    }
}
