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
    /// <summary>
    /// Gets the key size in bytes.
    /// </summary>
    public abstract int KeySizeBytes { get; }

    /// <summary>
    /// Gets the salt size in bytes.
    /// </summary>
    public abstract int SaltSizeBytes { get; }

    /// <summary>
    /// Encrypts the specified plaintext data.
    /// </summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Encrypt(byte[] publicKey, byte[] plaintext)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKey);

        var cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest());
        cipher.Init(true, asymmetricKeyParameter);

        byte[] ciphertext = cipher.ProcessBlock(plaintext, 0, plaintext.Length);
        return ciphertext;
    }

    /// <summary>
    /// Decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Decrypt(byte[] secretKey, byte[] encrypted)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.CreateKey(secretKey);

        var cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest());
        cipher.Init(false, asymmetricKeyParameter);

        byte[] plaintext = cipher.ProcessBlock(encrypted, 0, encrypted.Length);
        return plaintext;
    }

    /// <summary>
    /// Computes the digital signature for the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.CreateKey(secretKey);

        var signer = new RsaDigestSigner(new Sha256Digest());
        signer.Init(true, asymmetricKeyParameter);
        signer.BlockUpdate(message, 0, message.Length);

        byte[] signature = signer.GenerateSignature();
        return signature;
    }

    /// <summary>
    /// Verifies the digital signature of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <param name="signature">The digital signature to verify.</param>
    /// <param name="publicKey">The public key.</param>
    /// <returns>true if the verification succeeded; otherwise, false.</returns>
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKey);

        var signer = new RsaDigestSigner(new Sha256Digest());
        signer.Init(false, asymmetricKeyParameter);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.VerifySignature(signature);
    }

    /// <summary>
    /// Generates a new public/private key pair.
    /// </summary>
    /// <returns>A tuple containing the resulting values.</returns>
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
