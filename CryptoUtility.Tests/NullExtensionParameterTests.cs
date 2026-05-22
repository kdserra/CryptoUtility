using Xunit;
using CryptoUtility;

namespace CryptoUtility.Tests;

public class NullExtensionParameterTests
{
    [Fact]
    public void AsymmetricCipherExtensions_NullHandling()
    {
        IAsymmetricCipher? nullCipher = null;
        ISymmetricCipher? mockSymmetric = Aes256GcmImpl.Shared;

        // 1. EncryptBase64
        var (encSuccess, encResult) = nullCipher!.EncryptBase64("publicKey", "plaintext");
        Assert.False(encSuccess);
        Assert.Equal(string.Empty, encResult);

        // 2. DecryptBase64
        var (decSuccess, decResult) = nullCipher!.DecryptBase64("secretKey", "encrypted");
        Assert.False(decSuccess);
        Assert.Equal(string.Empty, decResult);

        // 3. GenerateKeyPairBase64
        var (pub, sec) = nullCipher!.GenerateKeyPairBase64();
        Assert.Equal(string.Empty, pub);
        Assert.Equal(string.Empty, sec);

        // 4. HybridEncrypt (with symmetric cipher)
        var (h1Success, h1Encrypted) = nullCipher!.HybridEncrypt(mockSymmetric, [1, 2], [3, 4]);
        Assert.False(h1Success);
        Assert.Empty(h1Encrypted);

        // 5. HybridDecrypt (with symmetric cipher)
        var (h1DecSuccess, h1Plaintext) = nullCipher!.HybridDecrypt(mockSymmetric, [1, 2], [3, 4]);
        Assert.False(h1DecSuccess);
        Assert.Empty(h1Plaintext);

        // 6. HybridEncrypt (with SymmetricCipherID)
        var (h2Success, h2Encrypted) = nullCipher!.HybridEncrypt([1, 2], [3, 4]);
        Assert.False(h2Success);
        Assert.Empty(h2Encrypted);

        // 7. HybridDecrypt (with SymmetricCipherID)
        var (h2DecSuccess, h2Plaintext) = nullCipher!.HybridDecrypt([1, 2], [3, 4]);
        Assert.False(h2DecSuccess);
        Assert.Empty(h2Plaintext);

        // 8. HybridEncryptBase64
        var (h3Success, h3Encrypted) = nullCipher!.HybridEncryptBase64("pubKey", "plain");
        Assert.False(h3Success);
        Assert.Equal(string.Empty, h3Encrypted);

        // 9. HybridDecryptBase64
        var (h3DecSuccess, h3Plaintext) = nullCipher!.HybridDecryptBase64("secKey", "enc");
        Assert.False(h3DecSuccess);
        Assert.Equal(string.Empty, h3Plaintext);
    }

    [Fact]
    public void DigitalSignatureExtensions_NullHandling()
    {
        IDigitalSignature? nullSig = null;

        // 1. SignBase64
        var (signSuccess, signature) = nullSig!.SignBase64("msg", "secKey");
        Assert.False(signSuccess);
        Assert.Equal(string.Empty, signature);

        // 2. VerifyBase64
        bool verifyResult = nullSig!.VerifyBase64("msg", "sig", "pubKey");
        Assert.False(verifyResult);

        // 3. GenerateKeyPairBase64
        var (pub, sec) = nullSig!.GenerateKeyPairBase64();
        Assert.Equal(string.Empty, pub);
        Assert.Equal(string.Empty, sec);
    }

    [Fact]
    public void HashProviderExtensions_NullHandling()
    {
        IHashProvider? nullHash = null;

        // 1. HashBase64
        string hash = nullHash!.HashBase64("message");
        Assert.Equal(string.Empty, hash);

        // 2. Sign
        byte[] sigBytes = nullHash!.Sign([1, 2], [3, 4]);
        Assert.Empty(sigBytes);

        // 3. SignBase64
        string sigStr = nullHash!.SignBase64("msg", "key");
        Assert.Equal(string.Empty, sigStr);

        // 4. Verify
        bool verifyResult = nullHash!.Verify([1, 2], [3, 4], [5, 6]);
        Assert.False(verifyResult);

        // 5. VerifyBase64
        bool verifyBase64Result = nullHash!.VerifyBase64("msg", "sig", "key");
        Assert.False(verifyBase64Result);
    }

    [Fact]
    public void KeyAgreementExtensions_NullHandling()
    {
        IKeyAgreement? nullAgreement = null;

        // 1. DeriveSharedSecretBase64
        var (deriveSuccess, secret) = nullAgreement!.DeriveSharedSecretBase64("secKey", "pubKey");
        Assert.False(deriveSuccess);
        Assert.Equal(string.Empty, secret);

        // 2. GenerateKeyPairBase64
        var (pub, sec) = nullAgreement!.GenerateKeyPairBase64();
        Assert.Equal(string.Empty, pub);
        Assert.Equal(string.Empty, sec);

        // 3. Encrypt
        var (encSuccess, encrypted) = nullAgreement!.Encrypt([1, 2], [3, 4], [5, 6], cipher: null, kdf: null);
        Assert.False(encSuccess);
        Assert.Empty(encrypted);

        // 4. Decrypt
        var (decSuccess, decrypted) = nullAgreement!.Decrypt([1, 2], [3, 4], [5, 6], cipher: null, kdf: null);
        Assert.False(decSuccess);
        Assert.Empty(decrypted);
    }

    [Fact]
    public void SymmetricCipherExtensions_NullHandling()
    {
        ISymmetricCipher? nullSymmetric = null;

        // 1. Encrypt
        var (encSuccess, encrypted) = nullSymmetric!.Encrypt([1, 2], [3, 4]);
        Assert.False(encSuccess);
        Assert.Empty(encrypted);

        // 2. EncryptBase64 (string, string)
        var (encBase64Success, encBase64) = nullSymmetric!.EncryptBase64("key", "plain");
        Assert.False(encBase64Success);
        Assert.Equal(string.Empty, encBase64);

        // 3. DecryptBase64 (string, string)
        var (decBase64Success, decBase64) = nullSymmetric!.DecryptBase64("key", "enc");
        Assert.False(decBase64Success);
        Assert.Equal(string.Empty, decBase64);

        // 4. EncryptBase64 (string, byte[])
        var (encBytesSuccess, encBytes) = nullSymmetric!.EncryptBase64("key", new byte[] { 1, 2 });
        Assert.False(encBytesSuccess);
        Assert.Empty(encBytes);

        // 5. DecryptBase64 (string, byte[])
        var (decBytesSuccess, decBytes) = nullSymmetric!.DecryptBase64("key", new byte[] { 1, 2 });
        Assert.False(decBytesSuccess);
        Assert.Empty(decBytes);

        // 6. GenerateKey
        byte[] key = nullSymmetric!.GenerateKey();
        Assert.Empty(key);

        // 7. GenerateNonce
        byte[] nonce = nullSymmetric!.GenerateNonce();
        Assert.Empty(nonce);

        // 8. GenerateNonceBase64
        string nonceBase64 = nullSymmetric!.GenerateNonceBase64();
        Assert.Equal(string.Empty, nonceBase64);

        // 9. GenerateKeyBase64
        string keyBase64 = nullSymmetric!.GenerateKeyBase64();
        Assert.Equal(string.Empty, keyBase64);
    }

    [Fact]
    public void PasswordKdfExtensions_NullHandling()
    {
        IPasswordKdf? nullKdf = null;

        // 1. DeriveKeyBase64
        string derived = nullKdf!.DeriveKeyBase64("pass", [1, 2], 1, 16);
        Assert.Equal(string.Empty, derived);
    }

    [Fact]
    public void KeyExpansionKdfExtensions_NullHandling()
    {
        IKeyExpansionKdf? nullKdf = null;

        // 1. DeriveKeyBase64
        string derived = nullKdf!.DeriveKeyBase64("ikm", "salt", "info", 1, 16);
        Assert.Equal(string.Empty, derived);
    }
}
