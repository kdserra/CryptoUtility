using System.Text;

namespace CryptoUtility.Tests;

public abstract class DigitalSignatureTests
{
    internal abstract IDigitalSignature Cipher { get; }

    protected (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        return Cipher.GenerateKeyPair();
    }

    protected byte[] GeneratePlaintext()
    {
        return Encoding.UTF8.GetBytes("Hello, world!");
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

    [Fact]
    public void SignVerify_Base64_Roundtrip()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okSign, signature) = Cipher.SignBase64(message, sec);
        Assert.True(okSign);
        Assert.False(string.IsNullOrEmpty(signature));

        var verified = Cipher.VerifyBase64(message, signature, pub);
        Assert.True(verified);
    }

    [Fact]
    public void VerifyBase64_ModifiedMessage_Fails()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okSign, signature) = Cipher.SignBase64(message, sec);
        Assert.True(okSign);

        var verified = Cipher.VerifyBase64("tampered", signature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void VerifyBase64_ModifiedSignature_Fails()
    {
        var (pub, sec) = Cipher.GenerateKeyPairBase64();
        string message = "hello world";

        var (okSign, signature) = Cipher.SignBase64(message, sec);
        Assert.True(okSign);

        var bytes = Convert.FromBase64String(signature);
        bytes[0] ^= 0xFF;
        string tamperedSignature = Convert.ToBase64String(bytes);

        var verified = Cipher.VerifyBase64(message, tamperedSignature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void SignBase64_WithEmptyMessage_Fails()
    {
        var (_, sec) = Cipher.GenerateKeyPairBase64();

        var (success, signature) = Cipher.SignBase64("", sec);

        Assert.False(success);
        Assert.True(string.IsNullOrEmpty(signature));
    }

    [Fact]
    public void SignBase64_WithInvalidKey_Fails()
    {
        var (success, signature) = Cipher.SignBase64("hello", "");

        Assert.False(success);
        Assert.True(string.IsNullOrEmpty(signature));
    }

    [Fact]
    public void VerifyBase64_WithInvalidInputs_Fails()
    {
        var result = Cipher.VerifyBase64("", "", "");
        Assert.False(result);
    }

    [Fact]
    public void VerifyBase64_WithNullInputs_Fails()
    {
        var result = Cipher.VerifyBase64(null!, null!, null!);
        Assert.False(result);
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

        signature[0] ^= 0xFF;

        var verified = Cipher.Verify(message, signature, pub);
        Assert.False(verified);
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
    public void DigitalSignatureExtensions_NullHandling()
    {
        IDigitalSignature? nullSig = null;

        var (signSuccess, signature) = nullSig!.SignBase64("msg", "secKey");
        Assert.False(signSuccess);
        Assert.Equal(string.Empty, signature);

        bool verifyResult = nullSig!.VerifyBase64("msg", "sig", "pubKey");
        Assert.False(verifyResult);

        var (pub, sec) = nullSig!.GenerateKeyPairBase64();
        Assert.Equal(string.Empty, pub);
        Assert.Equal(string.Empty, sec);
    }
}

