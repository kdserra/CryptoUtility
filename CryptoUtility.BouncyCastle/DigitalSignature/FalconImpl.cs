using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle FALCON Digital Signature implementation.
/// </summary>
[GenerateStaticApi]
public sealed class FalconImpl : IDigitalSignature
{
    /// <summary>
    /// The default FALCON parameters used by the shared instance (falcon_512).
    /// </summary>
    public static readonly FalconImpl Shared = new(FalconParameters.falcon_512);

    private readonly FalconParameters _parameters;

    /// <summary>
    /// Initializes a new instance of the <see cref="FalconImpl"/> class with default parameters (falcon_512).
    /// </summary>
    public FalconImpl() : this(FalconParameters.falcon_512)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FalconImpl"/> class with specified parameters.
    /// </summary>
    /// <param name="parameters">The FALCON parameters to use.</param>
    public FalconImpl(FalconParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    /// <inheritdoc />
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new FalconKeyGenerationParameters(random, _parameters);
        var generator = new FalconKeyPairGenerator();
        generator.Init(keyGenParameters);
        var keyPair = generator.GenerateKeyPair();

        byte[] pubBytes = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetEncoded();
        byte[] privBytes = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded();

        return (pubBytes, privBytes);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        LibraryHelper.ThrowIfAnyNull(message, secretKey);
        var privKey = (FalconPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(secretKey);

        var signer = new FalconSigner();
        signer.Init(true, privKey);

        return signer.GenerateSignature(message);
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        LibraryHelper.ThrowIfAnyNull(message, signature, publicKey);
        var pubKey = (FalconPublicKeyParameters)PqcPublicKeyFactory.CreateKey(publicKey);

        var signer = new FalconSigner();
        signer.Init(false, pubKey);

        return signer.VerifySignature(message, signature);
    }
}
