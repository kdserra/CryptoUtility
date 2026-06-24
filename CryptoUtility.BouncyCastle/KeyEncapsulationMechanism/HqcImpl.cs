using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HQC Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HqcImpl : IKeyEncapsulationMechanism
{
    /// <summary>
    /// The default HQC parameters used by the shared instance (hqc128).
    /// </summary>
    public static readonly HqcImpl Shared = new(HqcParameters.hqc128);

    private readonly HqcParameters _parameters;

    /// <inheritdoc />
    public int PublicKeySizeBytes { get; }

    /// <inheritdoc />
    public int SecretKeySizeBytes { get; }

    /// <inheritdoc />
    public int CiphertextSizeBytes { get; }

    /// <inheritdoc />
    public int SharedSecretSizeBytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="HqcImpl"/> class with default parameters (hqc128).
    /// </summary>
    public HqcImpl() : this(HqcParameters.hqc128)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HqcImpl"/> class with specified parameters.
    /// </summary>
    /// <param name="parameters">The HQC parameters to use.</param>
    public HqcImpl(HqcParameters parameters)
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
        var keyGenParameters = new HqcKeyGenerationParameters(random, _parameters);
        var generator = new HqcKeyPairGenerator();
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
        var pubKey = (HqcPublicKeyParameters)PqcPublicKeyFactory.CreateKey(peerPublicKey);

        var random = new SecureRandom();
        var generator = new HqcKemGenerator(random);
        var secretWithEnc = generator.GenerateEncapsulated(pubKey);

        return (secretWithEnc.GetSecret(), secretWithEnc.GetEncapsulation());
    }

    /// <inheritdoc />
    public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
    {
        LibraryHelper.ThrowIfAnyNull(secretKey, ciphertext);
        var privKey = (HqcPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(secretKey);

        var extractor = new HqcKemExtractor(privKey);
        return extractor.ExtractSecret(ciphertext);
    }
}
