using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Provides an Elliptic Curve Digital Signature Algorithm (ECDSA) implementation using the BouncyCastle cryptography
/// library using the NIST P-256 curve and SHA-256.
/// </summary>
[GenerateStaticApi]
public sealed class EcdsaImpl : IDigitalSignature
{
    public static readonly EcdsaImpl Shared = new();

    private const string Algorithm = "SHA-256withECDSA";
    private const string CurveName = "P-256";

    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        X9ECParameters ecParams = ECNamedCurveTable.GetByName(CurveName);
        ECDomainParameters domainParams = new(
            ecParams.Curve,
            ecParams.G,
            ecParams.N,
            ecParams.H,
            ecParams.GetSeed()
        );

        ECKeyPairGenerator generator = new();
        generator.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        byte[] publicKey = SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(keyPair.Public)
            .GetDerEncoded();
        byte[] privateKey = PrivateKeyInfoFactory
            .CreatePrivateKeyInfo(keyPair.Private)
            .GetDerEncoded();

        return (publicKey, privateKey);
    }

    public (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey)
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(message, secretKey))
            {
                return (false, Array.Empty<byte>());
            }

            AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.CreateKey(secretKey);

            ISigner signer = SignerUtilities.GetSigner(Algorithm);
            signer.Init(true, privateKeyParam);
            signer.BlockUpdate(message, 0, message.Length);

            byte[] signature = signer.GenerateSignature();
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

            AsymmetricKeyParameter publicKeyParam = PublicKeyFactory.CreateKey(publicKey);

            ISigner signer = SignerUtilities.GetSigner(Algorithm);
            signer.Init(false, publicKeyParam);
            signer.BlockUpdate(message, 0, message.Length);

            return signer.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }
}
