# 🔐 CryptoUtility

[![NuGet Version](https://img.shields.io/badge/nuget-v1.0.0-blue.svg)](https://nuget.org)
[![Target Framework](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-green.svg)](https://dotnet.microsoft.com)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE.txt)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com)

> **Cryptography, Done Right. Done Simply.**  
> Stop wrestling with nonces, authentication tags, and byte manipulation. CryptoUtility wraps standard, robust industry-grade ciphers in a zero-configuration, developer-first API so you can secure your apps in seconds.

---

## 💡 Why CryptoUtility? (The "Common Joe" Problem)

If you've ever tried to implement standard encryption in .NET, you know it's a minefield:
* **"What is a Nonce/IV?"** — If you reuse a nonce with ciphers like AES-GCM, your security is instantly broken. But generating, prepending, and parsing nonces requires hundreds of lines of fragile boilerplate.
* **"Where do I put the Authentication Tag?"** — Modern ciphers (AEAD) require an authentication tag to prevent hackers from tampering with your encrypted data. Storing and associating this tag is complex.
* **"How do I transmit it?"** — Sending the encrypted message, the IV, and the tag as separate database columns or API parameters is a nightmare.

### The CryptoUtility Solution
**We do the heavy lifting.** CryptoUtility packages the ciphertext, nonce, and authentication tag under the hood into a secure, lightweight **Symmetric Cipher Envelope** using `MemoryPack` (the ultra-fast binary serializer).

You call a single method. We handle the generation of cryptographically secure random nonces, authenticate the payload, and package it into a single base64 string or byte array. When decrypting, we unpack it automatically.

---

## ✨ Features at a Glance

* **Zero-Configuration APIs**: `GenerateKey()`, `Encrypt()`, `Decrypt()` — that's it.
* **Symmetric Encryption (AEAD)**: Secure, modern standards including **AES-256-GCM**, **AES-192-GCM**, **AES-128-GCM**, and **ChaCha20-Poly1305**.
* **Hybrid Encryption**: The speed of AES combined with the convenience of RSA. Encrypt huge payloads with public keys easily.
* **Asymmetric & Signatures**: Full support for **RSA-2048**, **RSA-4096**, and elliptic curve digital signatures (**ECDSA**).
* **Key Agreement (ECDH)**: Elliptic Curve Diffie-Hellman to let two parties safely establish a shared secret key over open channels.
* **Hashing & Checksums**: Standard hashes (SHA-256, SHA-3), fast non-cryptographic hashes (xxHash32/64/128), and integrity checksums (CRC-32, CRC-64).
* **Safety First**: Automatic zeroing of sensitive keys in memory (`CryptographicOperations.ZeroMemory`).

---

## 🚀 Quick Start in 60 Seconds

### 1. Symmetric Encryption (AES-256-GCM)
Encrypt files, database values, or session tokens in a few lines:

#### Base64 String Workflow (Perfect for JSON APIs & Databases)
```csharp
using CryptoUtility;

// 1. Generate a secure, random key
string base64Key = Aes256Gcm.GenerateKeyBase64();

// 2. Encrypt plaintext into a single, self-contained Base64 envelope
string plaintext = "Confidential customer details...";
var (encSuccess, envelope) = Aes256Gcm.EncryptBase64(base64Key, plaintext);

if (encSuccess)
{
    Console.WriteLine($"Secure Envelope: {envelope}");
    
    // 3. Decrypt on the other side with one call
    var (decSuccess, decryptedText) = Aes256Gcm.DecryptBase64(base64Key, envelope);
    Console.WriteLine($"Decrypted: {decryptedText}"); // Output: Confidential customer details...
}
```

#### Byte Array Workflow
```csharp
using CryptoUtility;

byte[] key = Aes256Gcm.GenerateKey();
byte[] plaintext = "Hello World"u8.ToArray();

var (success, encrypted) = Aes256Gcm.Encrypt(key, plaintext);
var (decSuccess, decrypted) = Aes256Gcm.Decrypt(key, encrypted);
```

---

### 2. Hybrid Asymmetric Encryption (RSA-4096 + AES)
RSA is great for key exchange but too slow for large payloads. Hybrid encryption automatically generates a temporary AES key, encrypts your large payload, encrypts the AES key using the recipient's RSA Public Key, and bundles them together.

```csharp
using CryptoUtility;

// Generate recipient's public/private keypair
var (publicKey, privateKey) = Rsa4096.GenerateKeyPairBase64();

// Encrypt payload using the PUBLIC key
string largePayload = "Highly confidential PDF database dump...";
var (encSuccess, envelope) = Rsa4096.HybridEncryptBase64(publicKey, largePayload);

// Decrypt payload using the PRIVATE key
var (decSuccess, decryptedPayload) = Rsa4096.HybridDecryptBase64(privateKey, envelope);
```

---

### 3. Key Agreement & Hybrid ECDH
Allow two users (Alice and Bob) to securely derive a matching symmetric key over an insecure channel, and immediately encrypt messages:

```csharp
using CryptoUtility;

// 1. Establish KeyPairs for Alice and Bob
var (alicePub, alicePriv) = Ecdh.GenerateKeyPair();
var (bobPub, bobPriv) = Ecdh.GenerateKeyPair();

// 2. Alice and Bob derive the SAME shared secret over the network
var (_, aliceSecret) = Ecdh.DeriveSharedSecret(alicePriv, bobPub);
var (_, bobSecret) = Ecdh.DeriveSharedSecret(bobPriv, alicePub);

// 3. Configure KDF parameters for session security
byte[] kdfSalt = "session-salt"u8.ToArray();
byte[] kdfInfo = "session-context-info"u8.ToArray();

// 4. Alice encrypts using her derived secret
var (_, ciphertext) = Ecdh.Encrypt(aliceSecret, "Hi Bob!", kdfSalt, kdfInfo);

// 5. Bob decrypts using his derived secret
var (_, decrypted) = Ecdh.Decrypt(bobSecret, ciphertext, kdfSalt, kdfInfo);
```

---

## 🛠️ Complete API List

| Category | Algorithm / Class | Description |
| :--- | :--- | :--- |
| **Symmetric AEAD** | `Aes256Gcm`, `Aes192Gcm`, `Aes128Gcm` | Industry gold standard authenticated encryption. |
| **Symmetric AEAD** | `ChaCha20Poly1305` | High-performance mobile-friendly stream cipher. |
| **Asymmetric** | `Rsa2048`, `Rsa4096` | Standard RSA asymmetric ciphers & Hybrid Encryption. |
| **Signatures** | `Ecdsa` | Elliptic Curve Digital Signatures (ECDSA P-256/384/521). |
| **Key Agreement**| `Ecdh` | Elliptic Curve Diffie-Hellman key derivation. |
| **Key Derivation**| `Pbkdf2`, `HkdfStandard` | Secure password hashing & cryptographic key expansion. |
| **Hashing** | `Sha256`, `Sha3_256` | Secure, standard hashes and HMAC authentication. |
| **Checksums** | `Crc32`, `Crc64`, `XxHash64` | Ultra-fast data integrity verification. |
| **Stream Ciphers**| `XorCipher` | Simple, fast byte-level XOR (strictly for light obfuscation). |

---

## 🔒 Security Best Practices Implemented Automatically

* **No Static Nonces**: CryptoUtility generates a high-entropy cryptographically secure random nonce for every single encryption.
* **Authentication-First**: We default to AEAD (Authenticated Encryption with Associated Data) ciphers like AES-GCM to prevent "bit-flipping" attacks.
* **Memory Sanitation**: Symmetric keys derived during key expansion/hybrid decryption are cleared from system RAM immediately after use.
* **Standard Algorithms**: We don't write custom crypto ciphers. We wrap native, Microsoft-vetted .NET `System.Security.Cryptography` implementations.

---

## 📦 Installation

To use CryptoUtility in your project, add the NuGet package:

```bash
dotnet add package CryptoUtility
```

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE.txt](LICENSE.txt) for details.
