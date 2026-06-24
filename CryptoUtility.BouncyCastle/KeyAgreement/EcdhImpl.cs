using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ECDH implementation using standard PKCS#8 and SPKI key formats with SHA-256 KDF parity.
/// </summary>
[GenerateStaticApi]
public sealed class EcdhImpl : IKeyAgreement
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly EcdhImpl Shared = new();

    private static readonly X9ECParameters EcParams = SecNamedCurves.GetByName("secp256r1");

    private static readonly ECDomainParameters DomainParams = new ECNamedDomainParameters(
        SecObjectIdentifiers.SecP256r1,
        EcParams.Curve,
        EcParams.G,
        EcParams.N,
        EcParams.H
    );

    /// <inheritdoc cref="IKeyAgreement.DeriveSharedSecret(byte[], byte[])"/>
    public byte[] DeriveSharedSecret(
        byte[] secretKey,
        byte[] peerPublicKey
    )
    {
        var privateKeyParam = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(secretKey);
        var publicKeyParam = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(peerPublicKey);

        var agreement = AgreementUtilities.GetBasicAgreement("ECDH");
        agreement.Init(privateKeyParam);
        var secretBigInt = agreement.CalculateAgreement(publicKeyParam);

        byte[] rawSecret = secretBigInt.ToByteArrayUnsigned();
        if (rawSecret.Length < 32)
        {
            byte[] paddedSecret = new byte[32];
            Array.Copy(rawSecret, 0, paddedSecret, 32 - rawSecret.Length, rawSecret.Length);
            rawSecret = paddedSecret;
        }

        var digest = new Sha256Digest();
        byte[] hashedSecret = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(rawSecret, 0, rawSecret.Length);
        digest.DoFinal(hashedSecret, 0);

        return hashedSecret;
    }

    /// <inheritdoc cref="IKeyAgreement.GenerateKeyPair()"/>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var keyGenParam = new ECKeyGenerationParameters(DomainParams, new SecureRandom());
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenParam);

        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        var rawPriv = (ECPrivateKeyParameters)keyPair.Private;
        var rawPub = (ECPublicKeyParameters)keyPair.Public;

        var namedPrivKey = new ECPrivateKeyParameters(rawPriv.D, DomainParams);
        var namedPubKey = new ECPublicKeyParameters(rawPub.Q, DomainParams);

        var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(namedPubKey);
        byte[] publicKeyBytes = publicKeyInfo.GetDerEncoded();

        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(namedPrivKey);
        byte[] secretKeyBytes = privateKeyInfo.GetDerEncoded();

        return (publicKeyBytes, secretKeyBytes);
    }
}
