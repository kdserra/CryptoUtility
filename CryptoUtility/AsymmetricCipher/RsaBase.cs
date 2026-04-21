#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

internal abstract class RsaBase : AsymmetricCipher
{
    public override (bool success, byte[] encrypted) Encrypt(byte[] publicKey, byte[] plaintext)
    {
        if (!CryptoHelper.ValidateAllParamsAreNotNullOrEmpty(publicKey, plaintext))
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

    public override (bool success, byte[] plaintext) Decrypt(byte[] secretKey, byte[] encrypted)
    {
        if (!CryptoHelper.ValidateAllParamsAreNotNullOrEmpty(secretKey, encrypted))
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

    public override (bool success, byte[] signature) Sign(byte[] input, byte[] secretKey)
    {
        if (!CryptoHelper.ValidateAllParamsAreNotNullOrEmpty(input, secretKey))
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

    public override bool Verify(byte[] input, byte[] signature, byte[] publicKey)
    {
        if (!CryptoHelper.ValidateAllParamsAreNotNullOrEmpty(input, signature, publicKey))
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

    public override (byte[] PublicKey, byte[] SecretKey) GenerateKey()
    {
        using RSA rsa = RSA.Create(KeySizeBytes * 8);
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        byte[] secretKeyBytes = rsa.ExportPkcs8PrivateKey();
        return (publicKeyBytes, secretKeyBytes);
    }
}

#endif
