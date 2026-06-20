using System.Text;

namespace CryptoUtility;

public static class DigitalSignatureExtensions
{
    public static (bool success, string signature) SignBase64(
        this IDigitalSignature digitalSignature,
        string message,
        string secretKey
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(digitalSignature, message, secretKey))
            {
                return (false, string.Empty);
            }

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
            (bool success, byte[] signatureBytes) = digitalSignature.Sign(
                messageBytes,
                secretKeyBytes
            );
            string signature = Convert.ToBase64String(signatureBytes);

            return (success, signature);
        }
        catch
        {
            return (false, string.Empty);
        }
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
            if (!LibraryHelper.NotNullOrEmpty(digitalSignature, message, signature, publicKey))
            {
                return false;
            }

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

    public static (string PublicKey, string SecretKey) GenerateKeyPairBase64(
        this IDigitalSignature digitalSignature
    )
    {
        if (!LibraryHelper.NotNull(digitalSignature))
        {
            return (string.Empty, string.Empty);
        }

        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = digitalSignature.GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }
}
