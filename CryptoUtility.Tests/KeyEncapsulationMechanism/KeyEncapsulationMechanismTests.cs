using System;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class KeyEncapsulationMechanismTests
{
    internal abstract IKeyEncapsulationMechanism Kem { get; }

    [Fact]
    public void Kem_RoundTrip_Succeeds()
    {
        var (publicKey, secretKey) = Kem.GenerateKeyPair();
        Assert.NotNull(publicKey);
        Assert.NotNull(secretKey);
        Assert.Equal(Kem.PublicKeySizeBytes, publicKey.Length);
        Assert.Equal(Kem.SecretKeySizeBytes, secretKey.Length);

        var (sharedSecret1, ciphertext) = Kem.Encapsulate(publicKey);
        Assert.NotNull(sharedSecret1);
        Assert.NotNull(ciphertext);
        Assert.Equal(Kem.SharedSecretSizeBytes, sharedSecret1.Length);
        Assert.Equal(Kem.CiphertextSizeBytes, ciphertext.Length);

        var sharedSecret2 = Kem.Decapsulate(secretKey, ciphertext);
        Assert.NotNull(sharedSecret2);
        Assert.Equal(Kem.SharedSecretSizeBytes, sharedSecret2.Length);

        Assert.Equal(sharedSecret1, sharedSecret2);
    }

    [Fact]
    public void Encapsulate_WithNullPublicKey_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Kem.Encapsulate(null!));
    }

    [Fact]
    public void Decapsulate_WithNullInputs_Throws()
    {
        var (pub, sec) = Kem.GenerateKeyPair();
        var (_, ciphertext) = Kem.Encapsulate(pub);

        Assert.ThrowsAny<Exception>(() => Kem.Decapsulate(null!, ciphertext));
        Assert.ThrowsAny<Exception>(() => Kem.Decapsulate(sec, null!));
    }

    [Fact]
    public void Kem_Sizes_MatchLiveImplementation()
    {
        var (publicKey, secretKey) = Kem.GenerateKeyPair();
        var (sharedSecret, ciphertext) = Kem.Encapsulate(publicKey);

        Assert.True(
            Kem.PublicKeySizeBytes == publicKey.Length,
            $"PublicKeySizeBytes mismatch for {Kem.GetType().Name}. Expected (Hardcoded): {Kem.PublicKeySizeBytes}, Actual (Live): {publicKey.Length}"
        );
        Assert.True(
            Kem.SecretKeySizeBytes == secretKey.Length,
            $"SecretKeySizeBytes mismatch for {Kem.GetType().Name}. Expected (Hardcoded): {Kem.SecretKeySizeBytes}, Actual (Live): {secretKey.Length}"
        );
        Assert.True(
            Kem.CiphertextSizeBytes == ciphertext.Length,
            $"CiphertextSizeBytes mismatch for {Kem.GetType().Name}. Expected (Hardcoded): {Kem.CiphertextSizeBytes}, Actual (Live): {ciphertext.Length}"
        );
        Assert.True(
            Kem.SharedSecretSizeBytes == sharedSecret.Length,
            $"SharedSecretSizeBytes mismatch for {Kem.GetType().Name}. Expected (Hardcoded): {Kem.SharedSecretSizeBytes}, Actual (Live): {sharedSecret.Length}"
        );
    }
}
