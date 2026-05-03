namespace CryptoUtility.Tests;

public abstract class SymmetricCipherAETests : SymmetricCipherTests
{
    internal ISymmetricCipherAE CipherAE => (ISymmetricCipherAE)Cipher;

    [Fact]
    public void Encrypt_CheckEnvelopeValidAE()
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
        Assert.NotEmpty(envelope.Tag);

        // Not required (allowed to be empty byte[]), just can't be null.
        Assert.NotNull(envelope.Aad);
    }
}
