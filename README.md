# 🔐 CryptoUtility

[![NuGet Version](https://img.shields.io/badge/nuget-v0.9.0-blue.svg)](https://nuget.org)
[![Target Framework](https://img.shields.io/badge/.NET-Standard%202.1%20|%208.0%20|%2010.0-green.svg)](https://dotnet.microsoft.com)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/kdserra/CryptoUtility/blob/master/LICENSE.md)
[![Build Status](https://img.shields.io/github/actions/workflow/status/kdserra/CryptoUtility/builder.yml?branch=master)](https://github.com/kdserra/CryptoUtility/actions/workflows/builder.yml)

> **Cryptography, Simplified & Unified.**  
> A developer-first cryptography abstraction library for .NET. Secure your data with state-of-the-art ciphers using a single, unified interface.

---

# ❓ Why CryptoUtility?

Standard cryptography APIs are notoriously complex, boilerplate-heavy, and easy to misconfigure. Because of this, developers often default to older, less secure options like `AES-CBC` simply because modern authenticated ciphers like `AES-GCM` are harder to set up.

CryptoUtility bridges this gap by offering:

## ⚡ State-of-the-Art Security, Simple APIs
With CryptoUtility, executing high-security authenticated encryption (AEAD) like **AES-256-GCM** or **ChaCha20-Poly1305** is just as straightforward as running a stateless cipher. All complex logic—such as secure nonce generation, authentication tag handling, and associated data verification—is managed automatically.

## 🧩 Unified Interfaces
We define clean, unified interfaces like `ISymmetricCipher`, `IAsymmetricCipher`, `IHashProvider`, `IKeyAgreement`, and `IPasswordKdf`. 

This is incredibly powerful for building modular application systems (such as a `SaveManager` or a networking layer). Your high-level managers can depend directly on `ISymmetricCipher` without being bound to a concrete implementation. You can swap your entire encryption algorithm from AES to ChaCha20 with a single line of code, without rewriting your business logic.

## 📦 Automatic Cryptographic Envelopes
For symmetric ciphers and hybrid encryption, CryptoUtility automatically packages the encrypted payload, random nonce, and authentication tag into a serialized cryptographic envelope under the hood using `MemoryPack` (an ultra-fast binary serializer). You receive a single, ready-to-transmit byte array or Base64 string. During decryption, the envelope is parsed automatically.

---

# ✨ Features

* **Unified API Design**: Identical syntax patterns for encryption, decryption, signatures, key agreement, and hashing.
* **Built-in Utilities**: Out-of-the-box helper methods for seamless **Base64 string operations** and **easy key generation** (`GenerateKey()`).
* **Symmetric Encryption (AEAD)**: Modern standards including **AES-256-GCM**, **AES-192-GCM**, **AES-128-GCM**, and **ChaCha20-Poly1305**.
* **Hybrid Encryption**: Encrypt large payloads easily using RSA public keys combined with the speed of AES-256-GCM under the hood.
* **Asymmetric & Signatures**: Full support for **RSA-2048**, **RSA-4096**, and elliptic curve digital signatures (**ECDSA**).
* **Key Agreement (ECDH)**: Establish secure session keys over open channels with Elliptic Curve Diffie-Hellman.
* **Hashing & Checksums**: SHA-2/3, fast non-cryptographic hashes (xxHash32/64/128), and integrity checksums (CRC-32, CRC-64).

---

# 🚀 Getting Started

## 1️⃣ Symmetric Encryption (AES-256-GCM)

### 🔤 Base64 String Workflow
```csharp
using CryptoUtility;

// 1. Generate a secure, random key as a Base64 string
string base64Key = Aes256Gcm.GenerateKeyBase64();

// 2. Encrypt plaintext into a self-contained Base64 envelope
string plaintext = "Confidential customer details...";
var (encSuccess, envelope) = Aes256Gcm.EncryptBase64(base64Key, plaintext);

if (encSuccess)
{
    // 3. Decrypt with a single call
    var (decSuccess, decryptedText) = Aes256Gcm.DecryptBase64(base64Key, envelope);
    Console.WriteLine($"Decrypted: {decryptedText}"); // Confidential customer details...
}
```

### 📦 Byte Array Workflow
```csharp
using CryptoUtility;

// 1. Generate key and plaintext bytes
byte[] key = Aes256Gcm.GenerateKey();
byte[] plaintext = "Hello World"u8.ToArray();

// 2. Encrypt and Decrypt
var (encSuccess, ciphertext) = Aes256Gcm.Encrypt(key, plaintext);
var (decSuccess, decrypted) = Aes256Gcm.Decrypt(key, ciphertext);
```

---

## 2️⃣ Hybrid Asymmetric Encryption (RSA-4096 + AES)

```csharp
using CryptoUtility;

// Generate public/private keypair
var (publicKey, privateKey) = Rsa4096.GenerateKeyPairBase64();

// Encrypt payload using the PUBLIC key
string largePayload = "Highly confidential PDF database dump...";
var (encSuccess, envelope) = Rsa4096.HybridEncryptBase64(publicKey, largePayload);

// Decrypt payload using the PRIVATE key
var (decSuccess, decryptedPayload) = Rsa4096.HybridDecryptBase64(privateKey, envelope);
```

---

## 3️⃣ Key Agreement & Hybrid ECDH

```csharp
using CryptoUtility;

// 1. Establish KeyPairs for Alice and Bob
var (alicePub, alicePriv) = Ecdh.GenerateKeyPair();
var (bobPub, bobPriv) = Ecdh.GenerateKeyPair();

// 2. Alice and Bob derive the SAME shared secret
var (_, aliceSecret) = Ecdh.DeriveSharedSecret(alicePriv, bobPub);
var (_, bobSecret) = Ecdh.DeriveSharedSecret(bobPriv, alicePub);

// 3. Configure KDF parameters for session security
byte[] kdfSalt = "session-salt"u8.ToArray();
byte[] kdfInfo = "session-context-info"u8.ToArray();

// 4. Encrypt and Decrypt using derived secrets
var (_, ciphertext) = Ecdh.Encrypt(aliceSecret, "Hi Bob!", kdfSalt, kdfInfo);
var (_, decrypted) = Ecdh.Decrypt(bobSecret, ciphertext, kdfSalt, kdfInfo);
```

---

# 📚 Complete API Reference

| Category | Algorithm / Class | Description |
| :--- | :--- | :--- |
| **Symmetric AEAD** | `Aes256Gcm`, `Aes192Gcm`, `Aes128Gcm`, `ChaCha20Poly1305` | Industry standard authenticated encryption. |
| **Symmetric Basic** | `XorCipher` | Basic, fast, weak cipher, useful for obfuscation purposes. |
| **Asymmetric** | `Rsa1024`, `Rsa2048`, `Rsa3072`, `Rsa4096` | Ciphers for public/key cryptography, with support for hybrid encryption. |
| **Signatures** | `Ecdsa` | Digital Signatures used for message verification. |
| **Key Agreement**| `Ecdh` | Shared key derivation algorithms. |
| **Key Derivation**| Official .NET `Hkdf`, [`HkdfDotNet`](https://github.com/samuel-lucas6/HKDF.NET), [`HkdfStandard`](https://github.com/andreimilto/HKDF.Standard)  | Secure cryptographic key expansion. |
| **Password Key Derivation**| `Pbkdf2` | Derivation of keys from passwords to strengthen against brute-force attacks. | 
| **Hashing** | `Sha1`, `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512`, `Crc32`, `Crc64`, `XxHash32`, `XxHash64`, `XxHash128` | Hashing algorithms, and checksums. |

**NOTE:** When available on the target platform, the native .NET implementation is used by default. Otherwise, the library automatically selects the most appropriate compatible implementation.

`HkdfDotNet` is provided for it's ease of inclusion into this library, backwards compatibility compared to the official .NET implementation which is limited to .NET 5 and above, but it's not as industry vetted as the official .NET HKDF, or HKDF.NET.  Included in the core CryptoUtility library.

`HkdfStandard` implementation is offered due to it's popularity, and it's backwards compatibility compared to the official .NET implementation which is limited to .NET 5 and above.  Requires `CryptoUtility.HkdfStandard`.

**PLANNED:** Bcrypt, Scrypt, Argon2id, maybe more.

---

# 🛡️ Security Best Practices

* **No Static Nonces**: CryptoUtility generates a unique, cryptographically secure random nonce for every single symmetric encryption.
* **Authentication-First**: We default to AEAD (Authenticated Encryption with Associated Data) ciphers to prevent bit-flipping and padding oracle attacks.
* **Memory Sanitation**: Sensitive derived keys are zeroed out of system memory immediately after use.
* **Standard Implementations**: We do not roll custom cryptographic algorithms. We wrap standard, industry-vetted implementations, except where one is not available.

---

# 📦 Installation

Add the NuGet package to your project:

```bash
dotnet add package CryptoUtility
```

---

# 📄 License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.
