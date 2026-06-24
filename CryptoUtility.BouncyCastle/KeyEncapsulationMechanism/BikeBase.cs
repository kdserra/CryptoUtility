using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle BIKE Key Encapsulation Mechanism implementations.
/// </summary>
public abstract class BikeBase : IKeyEncapsulationMechanism
{
    private readonly BikeParameters _parameters;

    /// <inheritdoc />
    public int PublicKeySizeBytes { get; }

    /// <inheritdoc />
    public int SecretKeySizeBytes { get; }

    /// <inheritdoc />
    public int CiphertextSizeBytes { get; }

    /// <inheritdoc />
    public int SharedSecretSizeBytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="BikeBase"/> class with the specified parameters.
    /// </summary>
    /// <param name="parameters">The BIKE parameters to use.</param>
    /// <param name="publicKeySizeBytes">The public key size in bytes.</param>
    /// <param name="secretKeySizeBytes">The secret key size in bytes.</param>
    /// <param name="ciphertextSizeBytes">The ciphertext size in bytes.</param>
    /// <param name="sharedSecretSizeBytes">The shared secret size in bytes.</param>
    protected BikeBase(
        BikeParameters parameters,
        int publicKeySizeBytes,
        int secretKeySizeBytes,
        int ciphertextSizeBytes,
        int sharedSecretSizeBytes
    )
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        PublicKeySizeBytes = publicKeySizeBytes;
        SecretKeySizeBytes = secretKeySizeBytes;
        CiphertextSizeBytes = ciphertextSizeBytes;
        SharedSecretSizeBytes = sharedSecretSizeBytes;
    }

    /// <inheritdoc />
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new BikeKeyGenerationParameters(random, _parameters);
        var generator = new BikeKeyPairGenerator();
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
    public (byte[] sharedSecret, byte[] ciphertext) Encapsulate(byte[] peerPublicKey)
    {
        LibraryHelper.ThrowIfNull(peerPublicKey);
        var pubKey = (BikePublicKeyParameters)PqcPublicKeyFactory.CreateKey(peerPublicKey);

        var random = new SecureRandom();
        var generator = new BikeKemGenerator(random);
        var secretWithEnc = generator.GenerateEncapsulated(pubKey);

        return (secretWithEnc.GetSecret(), secretWithEnc.GetEncapsulation());
    }

    /// <inheritdoc />
    public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
    {
        LibraryHelper.ThrowIfNull(secretKey);
        LibraryHelper.ThrowIfNull(ciphertext);
        var privKey = (BikePrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(secretKey);

        var extractor = new BikeKemExtractor(privKey);
        return extractor.ExtractSecret(ciphertext);
    }
}
