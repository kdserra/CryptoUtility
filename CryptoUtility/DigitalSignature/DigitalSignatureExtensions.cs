using System.Text;

namespace CryptoUtility;

public static class DigitalSignatureExtensions
{
    public static string SignBase64(
        this IDigitalSignature digitalSignature,
        string message,
        string secretKey
    )
    {
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] signatureBytes = digitalSignature.Sign(messageBytes, secretKeyBytes);
        string signatureBase64 = Convert.ToBase64String(signatureBytes);

        return signatureBase64;
    }

    public static bool VerifyBase64(
        this IDigitalSignature digitalSignature,
        string message,
        string signature,
        string publicKey
    )
    {
        try
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] signatureBytes = Convert.FromBase64String(signature);
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            bool isValid = digitalSignature.Verify(messageBytes, signatureBytes, publicKeyBytes);

            return isValid;
        }
        catch
        {
            return false;
        }
    }

    public static (string publicKey, string secretKey) GenerateKeyPairBase64(
        this IDigitalSignature digitalSignature
    )
    {
        (byte[] publicKeyBytes, byte[] secretKeyBytes) = digitalSignature.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(secretKeyBytes);

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
        string message,
        string secretKey,
        out string signature
    )
    {
        try
        {
            signature = digitalSignature.SignBase64(message, secretKey);

            return true;
        }
        catch
        {
            signature = string.Empty;

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
        out string publicKey,
        out string secretKey
    )
    {
        try
        {
            (string publicKey, string secretKey) result = digitalSignature.GenerateKeyPairBase64();
            publicKey = result.publicKey;
            secretKey = result.secretKey;

            return true;
        }
        catch
        {
            publicKey = string.Empty;
            secretKey = string.Empty;

            return false;
        }
    }
}
