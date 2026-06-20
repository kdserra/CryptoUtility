using System.Security.Cryptography;

namespace CryptoUtility.System;

/// <summary>
/// Provides Elliptic Curve Diffie-Hellman (ECDH) key agreement for securely sharing secrets between two parties.
/// </summary>
/// <remarks>
/// ECDH is a method that allows two people to create a shared secret over an insecure channel without sending the secret itself.
///
/// How it works in simple terms:
/// <list type="bullet">
/// <item>
/// <description>Each person generates a pair of keys: a private key (kept secret) and a public key (shared).</description>
/// </item>
/// <item>
/// <description>They exchange public keys with each other.</description>
/// </item>
/// <item>
/// <description>Each side combines their private key with the other person's public key to produce the same shared secret.</description>
/// </item>
/// </list>
///
/// This class handles:
/// <list type="bullet">
/// <item>
/// <description>Creating new ECDH key pairs using a standard secure curve (P-256).</description>
/// </item>
/// <item>
/// <description>Deriving a shared secret from a private key and a peer's public key.</description>
/// </item>
/// </list>
///
/// Important notes:
/// <list type="bullet">
/// <item>
/// <description>Secret keys must be kept secret and never shared.</description>
/// </item>
/// <item>
/// <description>Public keys are safe to share with others.</description>
/// </item>
/// <item>
/// <description>If invalid keys are provided, the operation fails safely instead of throwing an exception.</description>
/// </item>
/// </list>
/// </remarks>
[GenerateStaticApi]
public sealed class EcdhImpl : IKeyAgreement
{
    public static readonly EcdhImpl Shared = new();
    private static readonly ECCurve _defaultECCurve = ECCurve.NamedCurves.nistP256;

    /// <inheritdoc cref="IKeyAgreement.DeriveSharedSecret(byte[], byte[])"/>
    public (bool success, byte[] sharedSecret) DeriveSharedSecret(
        byte[] secretKey,
        byte[] peerPublicKey
    )
    {
        try
        {
            using var local = ECDiffieHellman.Create(_defaultECCurve);
            local.ImportPkcs8PrivateKey(secretKey, out _);

            using var peer = ECDiffieHellman.Create(_defaultECCurve);
            peer.ImportSubjectPublicKeyInfo(peerPublicKey, out _);

            byte[] secret = local.DeriveKeyMaterial(peer.PublicKey);
            return (true, secret);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <inheritdoc cref="IKeyAgreement.GenerateKeyPair()"/>
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        using var ecdh = ECDiffieHellman.Create(_defaultECCurve);
        byte[] publicKey = ecdh.ExportSubjectPublicKeyInfo();
        byte[] secretKey = ecdh.ExportPkcs8PrivateKey();
        return (publicKey, secretKey);
    }
}
