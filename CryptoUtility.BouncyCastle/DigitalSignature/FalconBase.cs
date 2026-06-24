using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle FALCON Digital Signature implementations.
/// </summary>
public abstract class FalconBase : IDigitalSignature
{
    private readonly FalconParameters _parameters;

    /// <summary>
    /// Initializes a new instance of the <see cref="FalconBase"/> class with the specified parameters.
    /// </summary>
    /// <param name="parameters">The FALCON parameters to use.</param>
    protected FalconBase(FalconParameters parameters)
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

        byte[] pubBytes = PqcSubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(keyPair.Public)
            .GetEncoded();
        byte[] privBytes = PqcPrivateKeyInfoFactory
            .CreatePrivateKeyInfo(keyPair.Private)
            .GetEncoded();

        return (pubBytes, privBytes);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(secretKey);
        var privKey = (FalconPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(secretKey);

        var signer = new FalconSigner();
        signer.Init(true, privKey);

        return signer.GenerateSignature(message);
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(signature);
        LibraryHelper.ThrowIfNull(publicKey);
        var pubKey = (FalconPublicKeyParameters)PqcPublicKeyFactory.CreateKey(publicKey);

        var signer = new FalconSigner();
        signer.Init(false, pubKey);

        return signer.VerifySignature(message, signature);
    }
}
