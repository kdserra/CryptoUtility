#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

internal abstract class RsaBase : AsymmetricCipher
{
    /// <inheritdoc cref="AsymmetricCipher.Encrypt(byte[], byte[])"/>
    public override (bool success, byte[] encrypted) Encrypt(byte[] publicKey, byte[] plaintext)
    {
        if (!LibraryHelper.NotNullOrEmpty(publicKey, plaintext))
        {
            return (false, Array.Empty<byte>());
        }

        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);

            byte[] encrypted = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
            return (true, encrypted);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <inheritdoc cref="AsymmetricCipher.Decrypt(byte[], byte[])"/>
    public override (bool success, byte[] plaintext) Decrypt(byte[] secretKey, byte[] encrypted)
    {
        if (!LibraryHelper.NotNullOrEmpty(secretKey, encrypted))
        {
            return (false, Array.Empty<byte>());
        }

        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(secretKey, out _);

            byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
            return (true, decrypted);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <inheritdoc cref="AsymmetricCipher.Sign(byte[], byte[])"/>
    public override (bool success, byte[] signature) Sign(byte[] input, byte[] secretKey)
    {
        if (!LibraryHelper.NotNullOrEmpty(input, secretKey))
        {
            return (false, Array.Empty<byte>());
        }

        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(secretKey, out _);

            byte[] signature = rsa.SignData(
                input,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
            return (true, signature);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <inheritdoc cref="AsymmetricCipher.Verify(byte[], byte[], byte[])"/>
    public override bool Verify(byte[] input, byte[] signature, byte[] publicKey)
    {
        if (!LibraryHelper.NotNullOrEmpty(input, signature, publicKey))
        {
            return false;
        }

        try
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
        catch
        {
            return false;
        }
    }

    /// <inheritdoc cref="AsymmetricCipher.GenerateKeyPair()"/>
    public override (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        using RSA rsa = RSA.Create(KeySizeBytes * 8);
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        byte[] secretKeyBytes = rsa.ExportPkcs8PrivateKey();
        return (publicKeyBytes, secretKeyBytes);
    }
}

#endif
