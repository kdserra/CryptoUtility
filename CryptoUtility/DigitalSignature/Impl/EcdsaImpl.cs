using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class EcdsaImpl : IDigitalSignature
{
    public static readonly EcdsaImpl Shared = new();

    public (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey)
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(message, secretKey))
            {
                return (false, Array.Empty<byte>());
            }

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(secretKey, out _);

            var signature = ecdsa.SignData(message, HashAlgorithmName.SHA256);
            return (true, signature);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(message, signature, publicKey))
            {
                return false;
            }

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            bool isValid = ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256);

            return isValid;
        }
        catch
        {
            return false;
        }
    }

    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        byte[] privateKey = ecdsa.ExportPkcs8PrivateKey();

        return (publicKey, privateKey);
    }
}
