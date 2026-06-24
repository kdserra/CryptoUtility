using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle BIKE Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class BikeImpl : IKeyEncapsulationMechanism
{
    /// <summary>
    /// The default BIKE parameters used by the shared instance (bike128).
    /// </summary>
    public static readonly BikeImpl Shared = new(BikeParameters.bike128);

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
    /// Initializes a new instance of the <see cref="BikeImpl"/> class with default parameters (bike128).
    /// </summary>
    public BikeImpl() : this(BikeParameters.bike128)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BikeImpl"/> class with specified parameters.
    /// </summary>
    /// <param name="parameters">The BIKE parameters to use.</param>
    public BikeImpl(BikeParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));

        // Measure sizes dynamically
        var (pub, priv) = GenerateKeyPair();
        PublicKeySizeBytes = pub.Length;
        SecretKeySizeBytes = priv.Length;

        var (secret, ct) = Encapsulate(pub);
        CiphertextSizeBytes = ct.Length;
        SharedSecretSizeBytes = secret.Length;
    }

    /// <inheritdoc />
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new BikeKeyGenerationParameters(random, _parameters);
        var generator = new BikeKeyPairGenerator();
        generator.Init(keyGenParameters);
        var keyPair = generator.GenerateKeyPair();

        byte[] pubBytes = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetEncoded();
        byte[] privBytes = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded();

        return (pubBytes, privBytes);
    }

    /// <inheritdoc />
    public (byte[] sharedSecret, byte[] ciphertext) Encapsulate(byte[] peerPublicKey)
    {
        LibraryHelper.ThrowIfAnyNull(peerPublicKey);
        var pubKey = (BikePublicKeyParameters)PqcPublicKeyFactory.CreateKey(peerPublicKey);

        var random = new SecureRandom();
        var generator = new BikeKemGenerator(random);
        var secretWithEnc = generator.GenerateEncapsulated(pubKey);

        return (secretWithEnc.GetSecret(), secretWithEnc.GetEncapsulation());
    }

    /// <inheritdoc />
    public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
    {
        LibraryHelper.ThrowIfAnyNull(secretKey, ciphertext);
        var privKey = (BikePrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(secretKey);

        var extractor = new BikeKemExtractor(privKey);
        return extractor.ExtractSecret(ciphertext);
    }
}
