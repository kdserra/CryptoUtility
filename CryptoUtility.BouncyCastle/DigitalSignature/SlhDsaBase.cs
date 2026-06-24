using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle SLH-DSA Digital Signature implementations.
/// </summary>
public abstract class SlhDsaBase : IDigitalSignature
{
    private readonly SlhDsaParameters _parameters;

    /// <summary>
    /// Initializes a new instance of the <see cref="SlhDsaBase"/> class with the specified parameters.
    /// </summary>
    /// <param name="parameters">The SLH-DSA parameters to use.</param>
    protected SlhDsaBase(SlhDsaParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    /// <inheritdoc />
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParameters = new SlhDsaKeyGenerationParameters(random, _parameters);
        var generator = new SlhDsaKeyPairGenerator();
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
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(secretKey);
        var privKey = (SlhDsaPrivateKeyParameters)
            Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(secretKey);

        var signer = new SlhDsaSigner(_parameters, deterministic: true);
        signer.Init(true, privKey);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.GenerateSignature();
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        LibraryHelper.ThrowIfNull(message);
        LibraryHelper.ThrowIfNull(signature);
        LibraryHelper.ThrowIfNull(publicKey);
        var pubKey = (SlhDsaPublicKeyParameters)
            Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(publicKey);

        var signer = new SlhDsaSigner(_parameters, deterministic: true);
        signer.Init(false, pubKey);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.VerifySignature(signature);
    }
}
