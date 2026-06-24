using System.Text;
using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleAes192GcmTests : SymmetricCipherAEADTests
{
    internal override ISymmetricCipher Cipher => Aes192GcmImpl.Shared;

    [Fact]
    public void Encrypt_BouncyCastleDecrypt_SystemAad_RoundTrip()
    {
        RunBouncyCastleToSystemAadRoundTrip(Aes192GcmImpl.Shared, CipherAEAD);
    }

    [Fact]
    public void Encrypt_SystemDecrypt_BouncyCastleAad_RoundTrip()
    {
        RunSystemToBouncyCastleAadRoundTrip(Aes192GcmImpl.Shared, CipherAEAD);
    }

    private static void RunBouncyCastleToSystemAadRoundTrip(
        ISymmetricCipherAEAD systemCipher,
        ISymmetricCipherAEAD bouncyCastleCipher
    )
    {
        byte[] key = systemCipher.GenerateKey();
        byte[] nonce = systemCipher.GenerateNonce();
        byte[] aad = Encoding.UTF8.GetBytes("associated data");
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-192-GCM interop");

        var encrypted = bouncyCastleCipher.Encrypt(key, plaintext, nonce, aad);
        var decrypted = systemCipher.Decrypt(key, encrypted, aad);
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
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-192-GCM interop");

        var encrypted = systemCipher.Encrypt(key, plaintext, nonce, aad);
        var decrypted = bouncyCastleCipher.Decrypt(key, encrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }
}
