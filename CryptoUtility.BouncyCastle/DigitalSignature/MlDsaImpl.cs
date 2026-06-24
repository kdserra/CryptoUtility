using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle ML-DSA Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class MlDsaImpl : IDigitalSignature
{
    /// <summary>
    /// The default ML-DSA parameters used by the shared instance (ML-DSA-65).
    /// </summary>
    public static readonly MlDsaImpl Shared = new(MLDsaParameters.ml_dsa_65);

    private readonly MLDsaParameters _parameters;

    /// <summary>
    /// Initializes a new instance of the <see cref="MlDsaImpl"/> class with default parameters (ML-DSA-65).
    /// </summary>
    public MlDsaImpl() : this(MLDsaParameters.ml_dsa_65)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MlDsaImpl"/> class with specified parameters.
    /// </summary>
    /// <param name="parameters">The ML-DSA parameters to use.</param>
    public MlDsaImpl(MLDsaParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    /// <inheritdoc />
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new MLDsaKeyGenerationParameters(random, _parameters);
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(keyGenParameters);
        var keyPair = generator.GenerateKeyPair();

        byte[] pubBytes = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetEncoded();
        byte[] privBytes = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded();

        return (pubBytes, privBytes);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        LibraryHelper.ThrowIfAnyNull(message, secretKey);
        var privKey = (MLDsaPrivateKeyParameters)Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(secretKey);

        var signer = new MLDsaSigner(_parameters, deterministic: true);
        signer.Init(true, privKey);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.GenerateSignature();
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        LibraryHelper.ThrowIfAnyNull(message, signature, publicKey);
        var pubKey = (MLDsaPublicKeyParameters)Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(publicKey);

        var signer = new MLDsaSigner(_parameters, deterministic: true);
        signer.Init(false, pubKey);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.VerifySignature(signature);
    }
}
