using System.Text;

namespace CryptoUtility.Tests;

public abstract class DigitalSignatureTests
{
    internal abstract IDigitalSignature Signer { get; }

    protected (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        return Signer.GenerateKeyPair();
    }

    protected byte[] GeneratePlaintext()
    {
        return Encoding.UTF8.GetBytes("Hello, world!");
    }

    [Fact]
    public abstract void Verify_AlgorithmSpecification();

    [Fact]
    public void Sign_WithNullKey_ThrowsOrFails()
    {
        var message = GeneratePlaintext();
        Assert.ThrowsAny<Exception>(() => Signer.Sign(message, null!));
    }

    [Fact]
    public void Sign_WithNullKey_Try_ReturnsFalse()
    {
        var message = GeneratePlaintext();
        bool success = Signer.TrySign(message, null!, out _);
        Assert.False(success);
    }

    [Fact]
    public void Verify_WithNullInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Signer.Verify(null!, null!, null!));
    }

    [Fact]
    public void SignVerify_Base64_Roundtrip()
    {
        var (pub, sec) = Signer.GenerateKeyPairBase64();
        string message = "hello world";

        var signature = Signer.SignBase64(message, sec);
        Assert.False(string.IsNullOrEmpty(signature));

        var verified = Signer.VerifyBase64(message, signature, pub);
        Assert.True(verified);
    }

    [Fact]
    public void SignVerify_Base64_Try_Roundtrip()
    {
        var (pub, sec) = Signer.GenerateKeyPairBase64();
        string message = "hello world";

        bool signSuccess = Signer.TrySignBase64(message, sec, out var signature);
        Assert.True(signSuccess);
        Assert.False(string.IsNullOrEmpty(signature));

        var verified = Signer.VerifyBase64(message, signature, pub);
        Assert.True(verified);
    }

    [Fact]
    public void VerifyBase64_ModifiedMessage_Fails()
    {
        var (pub, sec) = Signer.GenerateKeyPairBase64();
        string message = "hello world";

        var signature = Signer.SignBase64(message, sec);

        var verified = Signer.VerifyBase64("tampered", signature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void VerifyBase64_ModifiedSignature_Fails()
    {
        var (pub, sec) = Signer.GenerateKeyPairBase64();
        string message = "hello world";

        var signature = Signer.SignBase64(message, sec);

        var bytes = Convert.FromBase64String(signature);
        bytes[0] ^= 0xFF;
        string tamperedSignature = Convert.ToBase64String(bytes);

        var verified = Signer.VerifyBase64(message, tamperedSignature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void SignBase64_WithInvalidNullMessage_ThrowsOrFails()
    {
        var (_, sec) = Signer.GenerateKeyPairBase64();
        Assert.ThrowsAny<Exception>(() => Signer.SignBase64(null!, sec));
    }

    [Fact]
    public void SignBase64_WithInvalidKey_ThrowsOrFails()
    {
        Assert.ThrowsAny<Exception>(() => Signer.SignBase64("hello", ""));
    }

    [Fact]
    public void VerifyBase64_WithInvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Signer.VerifyBase64("", "", ""));
    }

    [Fact]
    public void VerifyBase64_WithNullInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Signer.VerifyBase64(null!, null!, null!));
    }

    [Fact]
    public void SignVerify_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        var signature = Signer.Sign(message, sec);
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);

        var verified = Signer.Verify(message, signature, pub);
        Assert.True(verified);
    }

    [Fact]
    public void SignVerify_Try_Roundtrip()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        bool signSuccess = Signer.TrySign(message, sec, out var signature);
        Assert.True(signSuccess);
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);

        var verified = Signer.Verify(message, signature, pub);
        Assert.True(verified);
    }

    [Fact]
    public void Verify_ModifiedMessage_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        var signature = Signer.Sign(message, sec);

        var tampered = Encoding.UTF8.GetBytes("tampered");

        var verified = Signer.Verify(tampered, signature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void Verify_ModifiedSignature_Fails()
    {
        var (pub, sec) = GenerateKeyPair();
        var message = GeneratePlaintext();

        var signature = Signer.Sign(message, sec);

        signature[0] ^= 0xFF;

        var verified = Signer.Verify(message, signature, pub);
        Assert.False(verified);
    }

    [Fact]
    public void Sign_WithInvalidEmptyKey_ThrowsOrFails()
    {
        var message = GeneratePlaintext();
        Assert.ThrowsAny<Exception>(() => Signer.Sign(message, []));
    }

    [Fact]
    public void Sign_WithInvalidNullMessage_ThrowsOrFails()
    {
        var (_, sec) = GenerateKeyPair();
        Assert.ThrowsAny<Exception>(() => Signer.Sign(null!, sec));
    }

    [Fact]
    public void Verify_WithInvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Signer.Verify([], [], []));
    }

    [Fact]
    public void DigitalSignatureExtensions_NullHandling_Try_ReturnsFalse()
    {
        IDigitalSignature? nullSig = null;

        Assert.False(nullSig!.TrySignBase64("msg", "secKey", out _));
        Assert.False(nullSig!.TryGenerateKeyPair(out _, out _));
        Assert.False(nullSig!.TryGenerateKeyPairBase64(out _, out _));
    }
}
