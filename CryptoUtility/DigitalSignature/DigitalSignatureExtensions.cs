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
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] signatureBytes = Convert.FromBase64String(signature);
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        bool isValid = digitalSignature.Verify(messageBytes, signatureBytes, publicKeyBytes);

        return isValid;
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
}
