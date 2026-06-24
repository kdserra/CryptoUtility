using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle ML-KEM Key Encapsulation Mechanism implementations.
/// </summary>
public abstract class MlKemBase : IKeyEncapsulationMechanism
{
    private readonly MLKemParameters _parameters;

    /// <inheritdoc />
    public int PublicKeySizeBytes { get; }

    /// <inheritdoc />
    public int SecretKeySizeBytes { get; }

    /// <inheritdoc />
    public int CiphertextSizeBytes { get; }

    /// <inheritdoc />
    public int SharedSecretSizeBytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MlKemBase"/> class with the specified parameters.
    /// </summary>
    /// <param name="parameters">The ML-KEM parameters to use.</param>
    protected MlKemBase(MLKemParameters parameters)
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
        var keyGenParameters = new MLKemKeyGenerationParameters(random, _parameters);
        var generator = new MLKemKeyPairGenerator();
        generator.Init(keyGenParameters);
        var keyPair = generator.GenerateKeyPair();

        byte[] pubBytes = Org
            .BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                keyPair.Public
            )
            .GetEncoded();
        byte[] privBytes = Org
            .BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private)
            .GetEncoded();

        return (pubBytes, privBytes);
    }

    /// <inheritdoc />
    public (byte[] sharedSecret, byte[] ciphertext) Encapsulate(byte[] peerPublicKey)
    {
        LibraryHelper.ThrowIfAnyNull(peerPublicKey);
        var pubKey = (MLKemPublicKeyParameters)
            Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(peerPublicKey);

        var encapsulator = new MLKemEncapsulator(_parameters);
        encapsulator.Init(pubKey);

        byte[] ciphertext = new byte[encapsulator.EncapsulationLength];
        byte[] sharedSecret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(
            ciphertext,
            0,
            ciphertext.Length,
            sharedSecret,
            0,
            sharedSecret.Length
        );

        return (sharedSecret, ciphertext);
    }

    /// <inheritdoc />
    public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
    {
        LibraryHelper.ThrowIfAnyNull(secretKey, ciphertext);
        var privKey = (MLKemPrivateKeyParameters)
            Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(secretKey);

        var decapsulator = new MLKemDecapsulator(_parameters);
        decapsulator.Init(privKey);

        byte[] sharedSecret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(
            ciphertext,
            0,
            ciphertext.Length,
            sharedSecret,
            0,
            sharedSecret.Length
        );

        return sharedSecret;
    }
}
