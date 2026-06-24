using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoUtility;

public static class KeyEncapsulationMechanismExtensions
{
    /// <summary>
    /// Generates a new key pair for the KEM.
    /// </summary>
    /// <returns>A tuple containing the public key and secret (private) key.</returns>
    public static (string publicKeyBase64, string secretKeyBase64) GenerateKeyPair(
        this IKeyEncapsulationMechanism kem
    )
    {
        (byte[] publicKey, byte[] secretKey) = kem.GenerateKeyPair();

        string publicKeyBase64 = Convert.ToBase64String(publicKey);
        string secretKeyBase64 = Convert.ToBase64String(secretKey);

        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(secretKey);

        return (publicKeyBase64, secretKeyBase64);
    }

    /// <summary>
    /// Encapsulates a shared secret using the peer's public key.
    /// </summary>
    /// <param name="peerPublicKeyBase64">The peer's public key bytes.</param>
    /// <returns>A tuple containing the derived shared secret and the encapsulated ciphertext.</returns>
    public static (string sharedSecretBase64, string ciphertextBase64) EncapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string peerPublicKeyBase64
    )
    {
        byte[] peerPublicKeyBytes = Convert.FromBase64String(peerPublicKeyBase64);
        (byte[] sharedSecret, byte[] ciphertext) = kem.Encapsulate(peerPublicKeyBytes);

        string sharedSecretBase64 = Convert.ToBase64String(sharedSecret);
        string ciphertextBase64 = Convert.ToBase64String(ciphertext);

        CryptographicOperations.ZeroMemory(peerPublicKeyBytes);
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(ciphertext);

        return (sharedSecretBase64, ciphertextBase64);
    }

    /// <summary>
    /// Decapsulates the ciphertext using the secret key to recover the shared secret.
    /// </summary>
    /// <param name="secretKeyBase64">The secret (private) key bytes.</param>
    /// <param name="ciphertextBase64">The encapsulated ciphertext bytes.</param>
    /// <returns>The recovered shared secret.</returns>
    public static string DecapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string secretKeyBase64,
        string ciphertextBase64
    )
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKeyBase64);
        byte[] ciphertextBytes = Convert.FromBase64String(ciphertextBase64);

        byte[] decapsulated = kem.Decapsulate(secretKeyBytes, ciphertextBytes);

        CryptographicOperations.ZeroMemory(secretKeyBytes);
        CryptographicOperations.ZeroMemory(ciphertextBytes);
        CryptographicOperations.ZeroMemory(decapsulated);

        string decapsulatedBase64 = Convert.ToBase64String(decapsulated);

        return decapsulatedBase64;
    }

    public static bool TryEncapsulate(
        this IKeyEncapsulationMechanism kem,
        byte[] peerPublicKey,
        out byte[] sharedSecret,
        out byte[] ciphertext
    )
    {
        try
        {
            (byte[] sharedSecret, byte[] ciphertext) result = kem.Encapsulate(peerPublicKey);

            sharedSecret = result.sharedSecret;
            ciphertext = result.ciphertext;
            return true;
        }
        catch
        {
            sharedSecret = Array.Empty<byte>();
            ciphertext = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryEncapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string peerPublicKeyBase64,
        out string sharedSecretBase64,
        out string ciphertextBase64
    )
    {
        try
        {
            (string sharedSecretBase64, string ciphertextBase64) result = kem.EncapsulateBase64(
                peerPublicKeyBase64
            );

            sharedSecretBase64 = result.sharedSecretBase64;
            ciphertextBase64 = result.ciphertextBase64;
            return true;
        }
        catch
        {
            sharedSecretBase64 = string.Empty;
            ciphertextBase64 = string.Empty;
            return false;
        }
    }

    public static bool TryDecapsulate(
        this IKeyEncapsulationMechanism kem,
        byte[] secretKey,
        byte[] ciphertext,
        out byte[] sharedSecret
    )
    {
        try
        {
            sharedSecret = kem.Decapsulate(secretKey, ciphertext);
            return true;
        }
        catch
        {
            sharedSecret = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryDecapsulateBase64(
        this IKeyEncapsulationMechanism kem,
        string secretKeyBase64,
        string ciphertextBase64,
        out string sharedSecretBase64
    )
    {
        try
        {
            sharedSecretBase64 = kem.DecapsulateBase64(secretKeyBase64, ciphertextBase64);
            return true;
        }
        catch
        {
            sharedSecretBase64 = string.Empty;
            return false;
        }
    }
}
