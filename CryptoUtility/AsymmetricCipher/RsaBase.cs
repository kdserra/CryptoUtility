#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

internal abstract class RsaBase : AsymmetricCipher
{
    public enum RsaKeySizeBits
    {
        KeySize_1024,
        KeySize_2048,
        KeySize_3072,
        KeySize_4096,
    }

    public override int KeySizeBytes { get; }

    protected RsaBase(RsaKeySizeBits keySize = RsaKeySizeBits.KeySize_2048)
    {
        KeySizeBytes = ConvertRsaKeySizeValueBytes(keySize);
    }

    public override (bool success, byte[] encrypted) Encrypt(byte[] publicKey, byte[] plaintext)
    {
        throw new NotImplementedException();
    }

    public override (bool success, byte[] plaintext) Decrypt(byte[] secretKey, byte[] encrypted)
    {
        throw new NotImplementedException();
    }

    public override (bool success, byte[] signature) Sign(byte[] input, byte[] secretKey)
    {
        throw new NotImplementedException();
    }

    public override bool Verify(byte[] input, byte[] signature, byte[] publicKey)
    {
        throw new NotImplementedException();
    }

    public override (byte[] PublicKey, byte[] SecretKey) GenerateKey()
    {
        using RSA rsa = RSA.Create(KeySizeBytes * 8);
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        byte[] secretKeyBytes = rsa.ExportPkcs8PrivateKey();
        return (publicKeyBytes, secretKeyBytes);
    }

    private int ConvertRsaKeySizeValueBytes(RsaKeySizeBits keySize)
    {
        switch (keySize)
        {
            case RsaKeySizeBits.KeySize_1024:
                return 1024 / 8;
            case RsaKeySizeBits.KeySize_2048:
                return 2048 / 8;
            case RsaKeySizeBits.KeySize_3072:
                return 3072 / 8;
            case RsaKeySizeBits.KeySize_4096:
                return 4096 / 8;
            default:
                throw new NotSupportedException();
        }
    }
}

#endif
