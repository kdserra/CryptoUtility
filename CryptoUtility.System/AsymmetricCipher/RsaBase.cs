#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// .NET implementation for RSA operations, handling key pair generation, OAEP-SHA256 encryption/decryption,
/// and SHA256-PKCS1 signing/verification.
/// </summary>
public abstract class RsaBase : IAsymmetricCipher, IDigitalSignature
{
    /// <inheritdoc cref="IAsymmetricCipher.KeySizeBytes"/>
    public abstract int KeySizeBytes { get; }

    /// <inheritdoc cref="IAsymmetricCipher.SaltSizeBytes"/>
    public abstract int SaltSizeBytes { get; }

    /// <inheritdoc cref="IAsymmetricCipher.Encrypt(byte[], byte[])"/>
    public byte[] Encrypt(byte[] publicKey, byte[] plaintext)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);

        byte[] ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        return ciphertext;
    }

    /// <inheritdoc cref="IAsymmetricCipher.Decrypt(byte[], byte[])"/>
    public byte[] Decrypt(byte[] secretKey, byte[] encrypted)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(secretKey, out _);

        byte[] plaintext = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
        return plaintext;
    }

    /// <inheritdoc cref="IDigitalSignature.Sign(byte[], byte[])"/>
    public byte[] Sign(byte[] input, byte[] secretKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(secretKey, out _);

        byte[] signature = rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return signature;
    }

    /// <inheritdoc cref="IDigitalSignature.Verify(byte[], byte[], byte[])"/>
    public bool Verify(byte[] input, byte[] signature, byte[] publicKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);

        return rsa.VerifyData(
            input,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }

    /// <inheritdoc cref="IAsymmetricCipher.GenerateKeyPair()"/>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        using RSA rsa = RSA.Create(KeySizeBytes * 8);
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        byte[] secretKeyBytes = rsa.ExportPkcs8PrivateKey();
        return (publicKeyBytes, secretKeyBytes);
    }
}

#endif
