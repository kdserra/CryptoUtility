using System.Text;
using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleAes256GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => new Aes256GcmImpl();

    [Fact]
    public void Encrypt_BouncyCastleDecrypt_SystemAad_RoundTrip()
    {
        RunBouncyCastleToSystemAadRoundTrip(new CryptoUtility.Aes256GcmImpl(), CipherAEAD);
    }

    [Fact]
    public void Encrypt_SystemDecrypt_BouncyCastleAad_RoundTrip()
    {
        RunSystemToBouncyCastleAadRoundTrip(new CryptoUtility.Aes256GcmImpl(), CipherAEAD);
    }

    private static void RunBouncyCastleToSystemAadRoundTrip(
        ISymmetricCipherAEAD systemCipher,
        ISymmetricCipherAEAD bouncyCastleCipher
    )
    {
        byte[] key = systemCipher.GenerateKey();
        byte[] nonce = systemCipher.GenerateNonce();
        byte[] aad = Encoding.UTF8.GetBytes("associated data");
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-256-GCM interop");

        var (encSuccess, encrypted) = bouncyCastleCipher.Encrypt(key, plaintext, nonce, aad);
        Assert.True(encSuccess);

        var (decSuccess, decrypted) = systemCipher.Decrypt(key, encrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }

    private static void RunSystemToBouncyCastleAadRoundTrip(
        ISymmetricCipherAEAD systemCipher,
        ISymmetricCipherAEAD bouncyCastleCipher
    )
    {
        byte[] key = systemCipher.GenerateKey();
        byte[] nonce = systemCipher.GenerateNonce();
        byte[] aad = Encoding.UTF8.GetBytes("associated data");
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-256-GCM interop");

        var (encSuccess, encrypted) = systemCipher.Encrypt(key, plaintext, nonce, aad);
        Assert.True(encSuccess);

        var (decSuccess, decrypted) = bouncyCastleCipher.Decrypt(key, encrypted);
        Assert.True(decSuccess);
        Assert.Equal(plaintext, decrypted);
    }
}
