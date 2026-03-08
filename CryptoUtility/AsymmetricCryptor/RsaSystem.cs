#if NET8_0_OR_GREATER
using System.Security.Cryptography;

namespace CryptoUtility;

public sealed class RsaSystem : AsymmetricCryptor
{
    public static readonly RsaSystem Shared1024 = new(RsaKeySizeBits.KeySize_1024);
    public static readonly RsaSystem Shared2048 = new(RsaKeySizeBits.KeySize_2048);
    public static readonly RsaSystem Shared3072 = new(RsaKeySizeBits.KeySize_3072);
    public static readonly RsaSystem Shared4096 = new(RsaKeySizeBits.KeySize_4096);
    public static readonly RsaSystem Shared = Shared2048;

    public enum RsaKeySizeBits
    {
        KeySize_1024,
        KeySize_2048,
        KeySize_3072,
        KeySize_4096,
    }

    public override int KeySizeBytes { get; }

    public RsaSystem(RsaKeySizeBits keySize = RsaKeySizeBits.KeySize_2048)
    {
        KeySizeBytes = ConvertRsaKeySizeValueBytes(keySize);
    }

    public override (byte[] PublicKey, byte[] SecretKey) GenerateKey()
    {
        using RSA rsa = RSA.Create(KeySizeBytes * 8);
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        byte[] secretKeyBytes = rsa.ExportPkcs8PrivateKey();
        return (publicKeyBytes, secretKeyBytes);
    }

    public override byte[] Encrypt(byte[] publicKey, byte[] value)
    {
        //byte[] keyNormalized = keyNormalizer.Normalize(publicKey, KeySizeBytes);
        throw new NotImplementedException();
    }

    public override byte[] Decrypt(byte[] secretKey, byte[] encryptedValue)
    {
        //byte[] keyNormalized = keyNormalizer.Normalize(secretKey, KeySizeBytes);
        throw new NotImplementedException();
    }

    public override byte[] Sign(byte[] input, byte[] secretKey)
    {
        //byte[] keyNormalized = keyNormalizer.Normalize(secretKey, KeySizeBytes);
        throw new NotImplementedException();
    }

    public override bool Verify(byte[] input, byte[] signature, byte[] publicKey)
    {
        //byte[] keyNormalized = keyNormalizer.Normalize(publicKey, KeySizeBytes);
        throw new NotImplementedException();
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
