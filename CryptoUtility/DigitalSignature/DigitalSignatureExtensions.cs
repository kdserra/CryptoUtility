using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class DigitalSignatureExtensions
{
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
