using System.Text;
using CryptoUtility;

Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine(
    "================================================================================"
);
Console.WriteLine(
    "                   CryptoUtility Feature Showcase & Tutorial                    "
);
Console.WriteLine(
    "================================================================================"
);
Console.ResetColor();
Console.WriteLine(
    "Welcome! This tutorial demonstrates how to use the CryptoUtility library to perform"
);
Console.WriteLine("various common cryptographic operations using standard, secure APIs.");

RunSymmetricShowcase();
RunAsymmetricAndHybridShowcase();
RunDigitalSignatureShowcase();
RunKeyAgreementShowcase();
RunKdfShowcase();
RunHashAndHmacShowcase();

Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine(
    "\n================================================================================"
);
Console.WriteLine(
    "                        Tutorial Completed Successfully!                       "
);
Console.WriteLine(
    "================================================================================"
);
Console.ResetColor();

#region Section Showcases

void RunSymmetricShowcase()
{
    PrintHeader("1. Symmetric Cryptography (AEAD & Standard)");

    Console.WriteLine("[AES-256-GCM AEAD Demonstration - Base64]");
    string plaintext = "The quick brown fox jumps over the lazy dog";

    string base64Key = Aes256Gcm.GenerateKeyBase64();

    Console.WriteLine($"  - Generated Key (Base64):  {base64Key}");
    Console.WriteLine($"  - Plaintext:               \"{plaintext}\"");

    var (encSuccess, encryptedEnvelope) = Aes256Gcm.EncryptBase64(base64Key, plaintext);
    if (encSuccess)
    {
        Console.WriteLine($"  - Encrypted Envelope:      {encryptedEnvelope}");

        var envelopeBytes = Convert.FromBase64String(encryptedEnvelope);
        var envelope = SymmetricCipherEnvelope.FromBytes(envelopeBytes);
        if (envelope != null)
        {
            Console.WriteLine($"    * Envelope Version:      {envelope.Version}");
            Console.WriteLine($"    * Nonce:                 {envelope.Nonce.ToHexString()}");
            Console.WriteLine($"    * Auth Tag:              {envelope.Tag.ToHexString()}");
            Console.WriteLine($"    * Associated Data (AAD): {envelope.Aad.ToHexString()}");
            Console.WriteLine($"    * Ciphertext:            {envelope.Ciphertext.ToHexString()}");
        }

        var (decSuccess, decrypted) = Aes256Gcm.DecryptBase64(base64Key, encryptedEnvelope);
        Console.WriteLine($"  - Decryption {(decSuccess ? "Succeeded!" : "Failed!")}");
        Console.WriteLine($"  - Decrypted Text:          \"{decrypted}\"");
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  - Encryption failed!");
        Console.ResetColor();
    }

    Console.WriteLine("\n[AES-256-GCM AEAD Demonstration - Advanced Byte-level]");
    byte[] byteKey = Aes256Gcm.GenerateKey();
    byte[] byteNonce = Aes256Gcm.GenerateNonce();
    byte[] bytePlaintext = Encoding.UTF8.GetBytes(plaintext);
    byte[] aad = Encoding.UTF8.GetBytes("Showcase-Metadata-AAD");

    Console.WriteLine($"  - Generated Key:           {byteKey.ToHexString(16)}");
    Console.WriteLine($"  - Generated Nonce:         {byteNonce.ToHexString(12)}");
    Console.WriteLine($"  - Plaintext:               \"{plaintext}\"");
    Console.WriteLine($"  - AAD Payload:             \"Showcase-Metadata-AAD\"");

    var (byteEncSuccess, byteEncEnvelopeBytes) = Aes256Gcm.Encrypt(
        byteKey,
        bytePlaintext,
        byteNonce,
        aad
    );
    if (byteEncSuccess)
    {
        Console.WriteLine($"  - Encrypted Envelope Bytes: {byteEncEnvelopeBytes.ToHexString(30)}");

        var (byteDecSuccess, byteDecryptedBytes) = Aes256Gcm.Decrypt(byteKey, byteEncEnvelopeBytes);
        string byteDecrypted = Encoding.UTF8.GetString(byteDecryptedBytes);
        Console.WriteLine($"  - Decryption {(byteDecSuccess ? "Succeeded!" : "Failed!")}");
        Console.WriteLine($"  - Decrypted Text:            \"{byteDecrypted}\"");
    }

    Console.WriteLine("\n[ChaCha20-Poly1305 AEAD Demonstration]");
    string base64KeyCC = CryptoUtility.ChaCha20Poly1305.GenerateKeyBase64();

    var (encCCSuccess, encryptedEnvelopeCC) = CryptoUtility.ChaCha20Poly1305.EncryptBase64(
        base64KeyCC,
        plaintext
    );
    if (encCCSuccess)
    {
        Console.WriteLine($"  - Encrypted Envelope:      {encryptedEnvelopeCC}");
        var (decCCSuccess, decryptedCC) = CryptoUtility.ChaCha20Poly1305.DecryptBase64(
            base64KeyCC,
            encryptedEnvelopeCC
        );
        Console.WriteLine($"  - Decrypted Text:          \"{decryptedCC}\"");
    }
}

void RunAsymmetricAndHybridShowcase()
{
    PrintHeader("2. Asymmetric Cryptography & Hybrid Encryption");

    string secretPayload =
        "This is a highly confidential document intended only for the recipient.";
    Console.WriteLine($"  - Original Payload: \"{secretPayload}\"\n");

    Console.WriteLine("[Standard RSA-2048 Asymmetric Encryption]");
    (string pubKey, string privKey) = Rsa2048.GenerateKeyPairBase64();
    Console.WriteLine(
        $"  - RSA Public Key (Base64 SubjectPublicKeyInfo):\n    {pubKey.Truncate(80)}"
    );
    Console.WriteLine($"  - RSA Private Key (Base64 PKCS8):\n    {privKey.Truncate(80)}");

    string smallMessage = "Meet at midnight.";
    var (encSuccess, encBytes) = Rsa2048.EncryptBase64(pubKey, smallMessage);
    if (encSuccess)
    {
        Console.WriteLine($"  - Encrypted Asymmetric Ciphertext:\n    {encBytes.Truncate(80)}");
        var (decSuccess, decText) = Rsa2048.DecryptBase64(privKey, encBytes);
        Console.WriteLine($"  - Decrypted Asymmetric Text: \"{decText}\"");
    }

    Console.WriteLine("\n[Hybrid Encryption (RSA-2048 + AES-256-GCM)]");
    var (hybridSuccess, hybridEnvelope) = Rsa2048.HybridEncryptBase64(pubKey, secretPayload);
    if (hybridSuccess)
    {
        Console.WriteLine(
            $"  - Encrypted Hybrid Envelope (Base64):\n    {hybridEnvelope.Truncate(80)}"
        );

        var (decHybridSuccess, decPayload) = Rsa2048.HybridDecryptBase64(privKey, hybridEnvelope);
        Console.WriteLine($"  - Decrypted Hybrid Payload: \"{decPayload}\"");
    }
}

void RunDigitalSignatureShowcase()
{
    PrintHeader("3. Digital Signatures (Authentication & Integrity)");

    string message = "Transaction Approval: Pay Alice $500.00";
    Console.WriteLine($"  - Message to Sign: \"{message}\"\n");

    Console.WriteLine("[RSA-2048 Digital Signatures]");
    (string rsaPub, string rsaPriv) = Rsa2048.GenerateKeyPairBase64();
    var (rsaSignSuccess, rsaSig) = Rsa2048.SignBase64(message, rsaPriv);
    if (rsaSignSuccess)
    {
        Console.WriteLine($"  - RSA Signature (Base64): {rsaSig.Truncate(60)}");
        bool isRsaValid = Rsa2048.VerifyBase64(message, rsaSig, rsaPub);
        Console.WriteLine($"  - RSA Signature is valid?  {isRsaValid}");

        bool isRsaValidTampered = Rsa2048.VerifyBase64(message + "!", rsaSig, rsaPub);
        Console.WriteLine($"  - RSA Signature is valid for tampered message? {isRsaValidTampered}");
    }

    Console.WriteLine("\n[ECDSA P-256 Digital Signatures]");
    (string ecdsaPub, string ecdsaPriv) = Ecdsa.GenerateKeyPairBase64();
    var (ecdsaSignSuccess, ecdsaSig) = Ecdsa.SignBase64(message, ecdsaPriv);
    if (ecdsaSignSuccess)
    {
        Console.WriteLine($"  - ECDSA Signature (Base64): {ecdsaSig.Truncate(60)}");
        bool isEcdsaValid = Ecdsa.VerifyBase64(message, ecdsaSig, ecdsaPub);
        Console.WriteLine($"  - ECDSA Signature is valid?  {isEcdsaValid}");
    }
}

void RunKeyAgreementShowcase()
{
    PrintHeader("4. Key Agreement (Elliptic Curve Diffie-Hellman)");

    (byte[] alicePub, byte[] alicePriv) = Ecdh.GenerateKeyPair();
    (byte[] bobPub, byte[] bobPriv) = Ecdh.GenerateKeyPair();

    Console.WriteLine($"  - Alice's Public Key: {alicePub.ToHexString(40)}");
    Console.WriteLine($"  - Bob's Public Key:   {bobPub.ToHexString(40)}\n");

    var (aliceSuccess, aliceSharedSecret) = Ecdh.DeriveSharedSecret(alicePriv, bobPub);

    var (bobSuccess, bobSharedSecret) = Ecdh.DeriveSharedSecret(bobPriv, alicePub);

    if (aliceSuccess && bobSuccess)
    {
        Console.WriteLine($"  - Alice derived secret: {aliceSharedSecret.ToHexString()}");
        Console.WriteLine($"  - Bob derived secret:   {bobSharedSecret.ToHexString()}");

        bool secretsMatch = aliceSharedSecret.SequenceEqual(bobSharedSecret);
        Console.ForegroundColor = secretsMatch ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(
            $"  - Do Alice and Bob's shared secrets match? {(secretsMatch ? "YES (Success)" : "NO (Failed)")}"
        );
        Console.ResetColor();

        Console.WriteLine("\n[Hybrid Key Agreement Encryption / Decryption Demo]");
        string plainText = "Hello Bob! This is Alice. Let's keep our communication secure.";
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] kdfSalt = "ECDH-HKDF-Salt"u8.ToArray();
        byte[] info = "ECDH-AES-GCM-HKDF-Context-Info"u8.ToArray();

        var (encSuccess, ciphertext) = Ecdh.Encrypt(aliceSharedSecret, plainBytes, kdfSalt, info);
        if (encSuccess)
        {
            Console.WriteLine($"  - Plaintext:            \"{plainText}\"");
            Console.WriteLine($"  - Context Info:         \"{Encoding.UTF8.GetString(info)}\"");
            Console.WriteLine($"  - Encrypted Ciphertext: {ciphertext.ToHexString(40)}");

            var (decSuccess, decryptedBytes) = Ecdh.Decrypt(
                bobSharedSecret,
                ciphertext,
                kdfSalt,
                info
            );

            if (decSuccess)
            {
                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  - Decrypted Text:       \"{decryptedText}\" (Success)");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  - Decryption failed!");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  - Encryption failed!");
            Console.ResetColor();
        }
    }
}

void RunKdfShowcase()
{
    PrintHeader("5. Key Derivation Functions (KDF)");

    Console.WriteLine("[PBKDF2 Password-to-Key Derivation]");
    string password = "MySuperSecurePassword123!";
    byte[] salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
    int iterations = 10000;
    int outputKeyBytes = 32;

    byte[] derivedPasswordKey = Pbkdf2.DeriveKey(password, salt, iterations, outputKeyBytes);
    Console.WriteLine($"  - Input Password: \"{password}\"");
    Console.WriteLine($"  - Random Salt:     {salt.ToHexString()}");
    Console.WriteLine($"  - Iterations:      {iterations}");
    Console.WriteLine($"  - Derived 256-bit key: {derivedPasswordKey.ToHexString()}");

    Console.WriteLine("\n[HKDF Key Expansion]");
    byte[] masterSecret = "transient-master-secret"u8.ToArray();
    byte[] hkdfSalt = "hkdf-salt-value"u8.ToArray();

    byte[] encryptionSubKey = CryptoUtility.HkdfDotNet.DeriveKey(
        masterSecret,
        1,
        32,
        hkdfSalt,
        [],
        System.Security.Cryptography.HashAlgorithmName.SHA256
    );
    byte[] signatureSubKey = CryptoUtility.HkdfDotNet.DeriveKey(
        masterSecret,
        1,
        32,
        hkdfSalt,
        [],
        System.Security.Cryptography.HashAlgorithmName.SHA384
    );

    Console.WriteLine($"  - Master Secret:      {masterSecret.ToHexString()}");
    Console.WriteLine($"  - Derived Enc SubKey: {encryptionSubKey.ToHexString()}");
    Console.WriteLine($"  - Derived MAC SubKey: {signatureSubKey.ToHexString()}");
}

void RunHashAndHmacShowcase()
{
    PrintHeader("6. Hash Providers & Checksums");

    string message = "Cryptographic hashing ensures data integrity.";
    byte[] messageBytes = Encoding.UTF8.GetBytes(message);

    Console.WriteLine("[SHA-256 & SHA3-256 Hashing]");
    byte[] sha256Hash = Sha256.Hash(messageBytes);
    byte[] sha3Hash = Sha3_256.Hash(messageBytes);

    Console.WriteLine($"  - Plain Message:     \"{message}\"");
    Console.WriteLine($"  - SHA-256 Hash:      {sha256Hash.ToHexString()}");
    Console.WriteLine($"  - SHA3-256 Hash:     {sha3Hash.ToHexString()}");

    Console.WriteLine("\n[xxHash64 Fast Hash (Non-cryptographic)]");
    byte[] xxHash = XxHash64.Hash(messageBytes);
    Console.WriteLine($"  - xxHash64 Hash:     {xxHash.ToHexString()}");

    Console.WriteLine("\n[CRC-32 Checksum]");
    byte[] crcBytes = Crc32.Hash(messageBytes);
    Console.WriteLine($"  - CRC-32 Checksum:   {crcBytes.ToHexString()}");

    Console.WriteLine("\n[HMAC Hashing Signatures]");
    string hmacKey = "secret-hmac-authentication-key";

    string hmacSig = Sha256.SignBase64(message, hmacKey);
    Console.WriteLine($"  - HMAC Signature:    {hmacSig}");

    bool isHmacValid = Sha256.VerifyBase64(message, hmacSig, hmacKey);
    Console.WriteLine($"  - HMAC is valid?     {isHmacValid}");
}

static void PrintHeader(string title)
{
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(new string('=', 65));
    Console.WriteLine($" {title}");
    Console.WriteLine(new string('=', 65));
    Console.ResetColor();
}

#endregion

Console.ReadLine();

public static class Extensions
{
    public static string ToHexString(this byte[]? bytes, int maxLength = 32)
    {
        if (bytes == null || bytes.Length == 0)
            return "empty";

        var sb = new StringBuilder();
        int len = Math.Min(bytes.Length, maxLength);
        for (int i = 0; i < len; i++)
        {
            sb.Append(bytes[i].ToString("x2"));
        }
        if (bytes.Length > maxLength)
        {
            sb.Append($"... ({bytes.Length} bytes)");
        }
        return sb.ToString();
    }

    public static string Truncate(this string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;
        if (text.Length <= maxLength)
            return text;

        return text.Substring(0, maxLength) + "...";
    }
}
