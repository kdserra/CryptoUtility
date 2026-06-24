using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Provides an Elliptic Curve Digital Signature Algorithm (ECDSA) implementation using the built-in .NET cryptography
/// library using the NIST P-256 curve and SHA-256.
/// </summary>
[GenerateStaticApi]
public sealed class EcdsaImpl : IDigitalSignature
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly EcdsaImpl Shared = new();
    /// <summary>
    /// Computes the digital signature for the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <returns>A byte array containing the result.</returns>

    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(secretKey, out _);

        byte[]? signature = ecdsa.SignData(message, HashAlgorithmName.SHA256);

        if (signature == null || signature.Length < 1)
        {
            throw new CryptographicException("Failed to generate signature");
        }

        return signature;
    }
    /// <summary>
    /// Verifies the digital signature of the specified input data.
    /// </summary>
    /// <param name="message">The input data to process.</param>
    /// <param name="signature">The digital signature to verify.</param>
    /// <param name="publicKey">The public key.</param>
    /// <returns>true if the verification succeeded; otherwise, false.</returns>

    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
        bool isValid = ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256);

        return isValid;
    }
    /// <summary>
    /// Generates a new public/private key pair.
    /// </summary>
    /// <returns>A tuple containing the resulting values.</returns>

    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        byte[] privateKey = ecdsa.ExportPkcs8PrivateKey();

        return (publicKey, privateKey);
    }
}
