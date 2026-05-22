using System.Text;

namespace CryptoUtility;

public static class DigitalSignatureExtensions
{
    /// <summary>
    /// Signs a Base64-encoded message using the specified secret key and returns the result as a Base64-encoded
    /// signature.
    /// </summary>
    /// <param name="digitalSignature">The digital signature instance used to perform the signing.</param>
    /// <param name="message">The Base64-encoded message to sign. Cannot be null.</param>
    /// <param name="secretKey">The Base64-encoded secret key used to sign the message. Cannot be null.</param>
    /// <returns>A tuple containing a value indicating whether the signing operation was successful and the Base64-encoded
    /// signature. The signature is an empty string if the operation fails.</returns>
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

    /// <summary>
    /// Verifies the authenticity of a message using its Base64-encoded signature and public key.
    /// </summary>
    /// <param name="digitalSignature">The digital signature instance used to perform the verification.</param>
    /// <param name="message">The message to verify. This parameter must not be null.</param>
    /// <param name="signature">The Base64-encoded digital signature associated with the message. This parameter must not be null.</param>
    /// <param name="publicKey">The Base64-encoded public key to use for signature verification. This parameter must not be null.</param>
    /// <returns>true if the signature is valid for the specified message and public key; otherwise, false.</returns>
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

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="digitalSignature">The digital signature instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
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
