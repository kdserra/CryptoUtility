namespace CryptoUtility.Tests;

public abstract class SymmetricCipherAETests : SymmetricCipherTests
{
    internal ISymmetricCipherAE CipherAE => (ISymmetricCipherAE)Cipher;

    [Fact]
    public void Encrypt_CheckEnvelopeValidAE()
    {
        var key = GenerateKey();
        var plaintext = GeneratePlaintext();

        var encrypted = Cipher.Encrypt(key, plaintext);

        Assert.NotNull(encrypted);

        int nonceLen = CipherAE.NonceSizeBytes;
        int tagLen = CipherAE.AuthTagSizeBytes;
        Assert.True(encrypted.Length >= nonceLen + tagLen);

        byte[] tag = new byte[tagLen];
        Buffer.BlockCopy(encrypted, encrypted.Length - tagLen, tag, 0, tagLen);

        Assert.NotEmpty(tag);
        Assert.Equal(tagLen, tag.Length);
    }
}
