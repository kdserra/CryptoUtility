namespace CryptoUtility.Tests;

public abstract class KeyAgreementTests
{
    internal abstract KeyAgreement KeyAgreement { get; }

    internal abstract KeyAgreement CreateNew();

    protected (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        return KeyAgreement.GenerateKeyPair();
    }

    protected byte[] GeneratePlaintext()
    {
        return System.Text.Encoding.UTF8.GetBytes("Hello, world!");
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

        var (okA, secretA) = a.DeriveSharedSecret(aSec, bPub);
        var (okB, secretB) = b.DeriveSharedSecret(bSec, aPub);

        Assert.True(okA);
        Assert.True(okB);
        Assert.NotEmpty(secretA);
        Assert.NotEmpty(secretB);
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void DeriveSharedSecret_InvalidInputs_Fail()
    {
        var (ok, secret) = KeyAgreement.DeriveSharedSecret([], []);

        Assert.False(ok);
        Assert.NotNull(secret);
        Assert.Empty(secret);
    }

    [Fact]
    public void DeriveSharedSecret_NullInputs_Fail()
    {
        var (ok, secret) = KeyAgreement.DeriveSharedSecret(null!, null!);

        Assert.False(ok);
        Assert.NotNull(secret);
        Assert.Empty(secret);
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

        var (okA, secretA) = a.DeriveSharedSecretBase64(aSec, bPub);
        var (okB, secretB) = b.DeriveSharedSecretBase64(bSec, aPub);

        Assert.True(okA);
        Assert.True(okB);
        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.False(string.IsNullOrEmpty(secretB));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void DeriveSharedSecretBase64_InvalidInputs_Fail()
    {
        var result = KeyAgreement.DeriveSharedSecretBase64("", "");
        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.sharedSecret));
    }

    [Fact]
    public void DeriveSharedSecretBase64_NullInputs_Fail()
    {
        var result = KeyAgreement.DeriveSharedSecretBase64(null!, null!);
        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.sharedSecret));
    }

    // =========================
    // Variation 1: same instance
    // =========================

    [Fact]
    public void SameInstance_SharedSecret_Roundtrip()
    {
        var a = KeyAgreement;
        var b = KeyAgreement;

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var (okA, secretA) = a.DeriveSharedSecret(aSec, bPub);
        var (okB, secretB) = b.DeriveSharedSecret(bSec, aPub);

        Assert.True(okA);
        Assert.True(okB);
        Assert.NotEmpty(secretA);
        Assert.NotEmpty(secretB);
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void SameInstance_DeriveSharedSecret_InvalidInputs_Fail()
    {
        var (ok, secret) = KeyAgreement.DeriveSharedSecret([], []);

        Assert.False(ok);
        Assert.NotNull(secret);
        Assert.Empty(secret);
    }

    [Fact]
    public void SameInstance_DeriveSharedSecret_NullInputs_Fail()
    {
        var (ok, secret) = KeyAgreement.DeriveSharedSecret(null!, null!);

        Assert.False(ok);
        Assert.NotNull(secret);
        Assert.Empty(secret);
    }

    [Fact]
    public void SameInstance_Base64_SharedSecret_Roundtrip()
    {
        var a = KeyAgreement;
        var b = KeyAgreement;

        var (aPub, aSec) = a.GenerateKeyPairBase64();
        var (bPub, bSec) = b.GenerateKeyPairBase64();

        var (okA, secretA) = a.DeriveSharedSecretBase64(aSec, bPub);
        var (okB, secretB) = b.DeriveSharedSecretBase64(bSec, aPub);

        Assert.True(okA);
        Assert.True(okB);
        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.False(string.IsNullOrEmpty(secretB));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void SameInstance_DeriveSharedSecretBase64_InvalidInputs_Fail()
    {
        var result = KeyAgreement.DeriveSharedSecretBase64("", "");

        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.sharedSecret));
    }

    [Fact]
    public void SameInstance_DeriveSharedSecretBase64_NullInputs_Fail()
    {
        var result = KeyAgreement.DeriveSharedSecretBase64(null!, null!);

        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.sharedSecret));
    }

    // =========================
    // Variation 2: new instance used for both sides
    // =========================

    [Fact]
    public void NewInstance_SharedSecret_Roundtrip()
    {
        var a = CreateNew();
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPair();
        var (bPub, bSec) = b.GenerateKeyPair();

        var (okA, secretA) = a.DeriveSharedSecret(aSec, bPub);
        var (okB, secretB) = b.DeriveSharedSecret(bSec, aPub);

        Assert.True(okA);
        Assert.True(okB);
        Assert.NotEmpty(secretA);
        Assert.NotEmpty(secretB);
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void NewInstance_DeriveSharedSecret_InvalidInputs_Fail()
    {
        var a = CreateNew();

        var (ok, secret) = a.DeriveSharedSecret([], []);

        Assert.False(ok);
        Assert.NotNull(secret);
        Assert.Empty(secret);
    }

    [Fact]
    public void NewInstance_DeriveSharedSecret_NullInputs_Fail()
    {
        var a = CreateNew();

        var (ok, secret) = a.DeriveSharedSecret(null!, null!);

        Assert.False(ok);
        Assert.NotNull(secret);
        Assert.Empty(secret);
    }

    [Fact]
    public void NewInstance_Base64_SharedSecret_Roundtrip()
    {
        var a = CreateNew();
        var b = CreateNew();

        var (aPub, aSec) = a.GenerateKeyPairBase64();
        var (bPub, bSec) = b.GenerateKeyPairBase64();

        var (okA, secretA) = a.DeriveSharedSecretBase64(aSec, bPub);
        var (okB, secretB) = b.DeriveSharedSecretBase64(bSec, aPub);

        Assert.True(okA);
        Assert.True(okB);
        Assert.False(string.IsNullOrEmpty(secretA));
        Assert.False(string.IsNullOrEmpty(secretB));
        Assert.Equal(secretA, secretB);
    }

    [Fact]
    public void NewInstance_DeriveSharedSecretBase64_InvalidInputs_Fail()
    {
        var a = CreateNew();

        var result = a.DeriveSharedSecretBase64("", "");

        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.sharedSecret));
    }

    [Fact]
    public void NewInstance_DeriveSharedSecretBase64_NullInputs_Fail()
    {
        var a = CreateNew();

        var result = a.DeriveSharedSecretBase64(null!, null!);

        Assert.False(result.success);
        Assert.True(string.IsNullOrEmpty(result.sharedSecret));
    }
}
