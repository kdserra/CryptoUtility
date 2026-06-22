using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle implementation for RSA operations, handling key pair generation, OAEP-SHA256 encryption/decryption,
/// and SHA256-PKCS1 signing/verification.
/// </summary>
public abstract class RsaBase : IAsymmetricCipher, IDigitalSignature
{
    public abstract int KeySizeBytes { get; }

    public abstract int SaltSizeBytes { get; }

    public byte[] Encrypt(byte[] publicKey, byte[] plaintext)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKey);

        var cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest());
        cipher.Init(true, asymmetricKeyParameter);

        byte[] ciphertext = cipher.ProcessBlock(plaintext, 0, plaintext.Length);
        return ciphertext;
    }

    public byte[] Decrypt(byte[] secretKey, byte[] encrypted)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.CreateKey(secretKey);

        var cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest());
        cipher.Init(false, asymmetricKeyParameter);

        byte[] plaintext = cipher.ProcessBlock(encrypted, 0, encrypted.Length);
        return plaintext;
    }

    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.CreateKey(secretKey);

        var signer = new RsaDigestSigner(new Sha256Digest());
        signer.Init(true, asymmetricKeyParameter);
        signer.BlockUpdate(message, 0, message.Length);

        byte[] signature = signer.GenerateSignature();
        return signature;
    }

    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKey);

        var signer = new RsaDigestSigner(new Sha256Digest());
        signer.Init(false, asymmetricKeyParameter);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.VerifySignature(signature);
    }

    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var keyGenerationParameters = new KeyGenerationParameters(
            new SecureRandom(),
            KeySizeBytes * 8
        );
        var generator = new RsaKeyPairGenerator();
        generator.Init(keyGenerationParameters);

        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        byte[] publicKeyBytes = SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(keyPair.Public)
            .GetDerEncoded();
        byte[] secretKeyBytes = PrivateKeyInfoFactory
            .CreatePrivateKeyInfo(keyPair.Private)
            .GetDerEncoded();

        return (publicKeyBytes, secretKeyBytes);
    }
}
