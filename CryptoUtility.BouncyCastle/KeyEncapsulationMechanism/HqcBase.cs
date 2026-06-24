using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle HQC Key Encapsulation Mechanism implementations.
/// </summary>
public abstract class HqcBase : IKeyEncapsulationMechanism
{
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
    /// Initializes a new instance of the <see cref="HqcBase"/> class with the specified parameters.
    /// </summary>
    /// <param name="parameters">The HQC parameters to use.</param>
    protected HqcBase(
        HqcParameters parameters,
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
        var keyGenParameters = new HqcKeyGenerationParameters(random, _parameters);
        var generator = new HqcKeyPairGenerator();
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
