using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;
    /// <summary>
    /// Provides extension methods for simplified digital signature computation and verification.
    /// </summary>

public static class DigitalSignatureExtensions
{
    /// <summary>
    /// Computes the digital signature for the specified input data using Base64-encoded strings.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <param name="secretKeyBase64">The Base64-encoded private (secret) key.</param>
    /// <returns>A string containing the result.</returns>
    public static string SignBase64(
        this IDigitalSignature digitalSignature,
        string messageUtf8,
        string secretKeyBase64
    )
    {
        byte[] messageBytes = Array.Empty<byte>();
        byte[] secretKeyBytes = Array.Empty<byte>();
        byte[] signatureBytes = Array.Empty<byte>();
        string signatureBase64 = string.Empty;

        try
        {
            messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
            secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
            signatureBytes = digitalSignature.Sign(messageBytes, secretKeyBytes);

            signatureBase64 = Convert.ToBase64String(signatureBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(secretKeyBytes);
            CryptographicOperations.ZeroMemory(signatureBytes);
        }

        return signatureBase64;
    }
    /// <summary>
    /// Verifies the digital signature of the specified input data using Base64-encoded strings.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <param name="signatureBase64">The Base64-encoded digital signature.</param>
    /// <param name="publicKeyBase64">The Base64-encoded public key.</param>
    /// <returns>true if the verification succeeded; otherwise, false.</returns>

    public static bool VerifyBase64(
        this IDigitalSignature digitalSignature,
        string messageUtf8,
        string signatureBase64,
        string publicKeyBase64
    )
    {
        byte[] messageBytes = Array.Empty<byte>();
        byte[] signatureBytes = Array.Empty<byte>();
        byte[] publicKeyBytes = Array.Empty<byte>();
        bool isValid = false;

        try
        {
            messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
            signatureBytes = Convert.FromBase64String(signatureBase64);
            publicKeyBytes = Convert.FromBase64String(publicKeyBase64);

            isValid = digitalSignature.Verify(messageBytes, signatureBytes, publicKeyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(signatureBytes);
            CryptographicOperations.ZeroMemory(publicKeyBytes);
        }

        return isValid;
    }
    /// <summary>
    /// Generates a new public/private key pair using Base64-encoded strings.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <returns>A tuple containing the resulting values.</returns>

    public static (string publicKeyBase64, string secretKeyBase64) GenerateKeyPairBase64(
        this IDigitalSignature digitalSignature
    )
    {
        byte[] publicKeyBytes = Array.Empty<byte>();
        byte[] secretKeyBytes = Array.Empty<byte>();
        string publicKeyBase64 = string.Empty;
        string secretKeyBase64 = string.Empty;

        try
        {
            (publicKeyBytes, secretKeyBytes) = digitalSignature.GenerateKeyPair();

            publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
            secretKeyBase64 = Convert.ToBase64String(secretKeyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
            CryptographicOperations.ZeroMemory(secretKeyBytes);
        }

        return (publicKeyBase64, secretKeyBase64);
    }
    /// <summary>
    /// Attempts to computes the digital signature for the specified input data.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <param name="message">The input data to process.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <param name="signature">The digital signature to verify.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

    public static bool TrySign(
        this IDigitalSignature digitalSignature,
        byte[] message,
        byte[] secretKey,
        out byte[] signature
    )
    {
        try
        {
            signature = digitalSignature.Sign(message, secretKey);

            return true;
        }
        catch
        {
            signature = Array.Empty<byte>();

            return false;
        }
    }
    /// <summary>
    /// Attempts to computes the digital signature for the specified input data using base64-encoded strings.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <param name="secretKeyBase64">The Base64-encoded private (secret) key.</param>
    /// <param name="signatureBase64">The Base64-encoded digital signature.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

    public static bool TrySignBase64(
        this IDigitalSignature digitalSignature,
        string messageUtf8,
        string secretKeyBase64,
        out string signatureBase64
    )
    {
        try
        {
            signatureBase64 = digitalSignature.SignBase64(messageUtf8, secretKeyBase64);

            return true;
        }
        catch
        {
            signatureBase64 = string.Empty;

            return false;
        }
    }
    /// <summary>
    /// Attempts to generates a new public/private key pair.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <param name="publicKey">The public key.</param>
    /// <param name="secretKey">The private (secret) key.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

    public static bool TryGenerateKeyPair(
        this IDigitalSignature digitalSignature,
        out byte[] publicKey,
        out byte[] secretKey
    )
    {
        try
        {
            (byte[] publicKey, byte[] secretKey) keyPair = digitalSignature.GenerateKeyPair();

            publicKey = keyPair.publicKey;
            secretKey = keyPair.secretKey;

            return true;
        }
        catch
        {
            publicKey = Array.Empty<byte>();
            secretKey = Array.Empty<byte>();

            return false;
        }
    }
    /// <summary>
    /// Attempts to generates a new public/private key pair using base64-encoded strings.
    /// </summary>
    /// <param name="digitalSignature">The digital signature.</param>
    /// <param name="publicKeyBase64">The Base64-encoded public key.</param>
    /// <param name="secretKeyBase64">The Base64-encoded private (secret) key.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

    public static bool TryGenerateKeyPairBase64(
        this IDigitalSignature digitalSignature,
        out string publicKeyBase64,
        out string secretKeyBase64
    )
    {
        try
        {
            (string publicKeyBase64, string secretKeyBase64) result =
                digitalSignature.GenerateKeyPairBase64();

            publicKeyBase64 = result.publicKeyBase64;
            secretKeyBase64 = result.secretKeyBase64;

            return true;
        }
        catch
        {
            publicKeyBase64 = string.Empty;
            secretKeyBase64 = string.Empty;

            return false;
        }
    }
}
