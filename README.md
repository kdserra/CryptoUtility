# 🔐 CryptoUtility

[![NuGet Version](https://img.shields.io/badge/nuget-v0.14.0-blue.svg)](https://www.nuget.org/packages/CryptoUtility)
[![Target Framework](https://img.shields.io/badge/.NET-Standard%202.1%20|%208.0%20|%2010.0-green.svg)](https://dotnet.microsoft.com)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/kdserra/CryptoUtility/blob/master/LICENSE.md)
[![Build Status](https://img.shields.io/github/actions/workflow/status/kdserra/CryptoUtility/builder.yml?branch=master)](https://github.com/kdserra/CryptoUtility/actions/workflows/builder.yml)

> **Cryptography, Simplified & Unified.**  
> A developer-first cryptography abstraction library for .NET. Secure your data with state-of-the-art ciphers using a single, unified interface.

---

# ❓ Why CryptoUtility?
CryptoUtility makes it quick, simple, and easy to work with cryptography.

We provide commonly requested utilities like Base64 support, unified interfaces that make it easy to swap implementations, or abstract dependencies, and provide backwards compatible implementations for common cryptographic operations.

CryptoUtility enables access to an entire ecosystem; no longer requiring you to learn different crypto APIs for different libraries.  In our library, using an authenticated cipher is just as simple and easy as a stateless cipher.  You no longer have to manage `IDisposable` objects and risk memory leaks as our wrappers deal with them.

This keeps your focus where it belongs: writing your application.

## ⚡ State-of-the-Art Security, Simple APIs
With CryptoUtility, executing high-security authenticated encryption (AEAD) like **AES-256-GCM** or **ChaCha20-Poly1305** is just as straightforward as running a stateless cipher. All complex logic—such as secure nonce generation, authentication tag handling, and associated data verification—is managed automatically.

## 🧩 Unified Interfaces
We define clean, unified interfaces like `ISymmetricCipher`, `IAsymmetricCipher`, `IKeyAgreement`, `IDigitalSignature`, `IHashProvider`, `IMacProvider`, `IKeyExpansionKdf`, and `IPasswordKdf`.

This is incredibly powerful for building modular application systems (such as a `SaveManager` or a networking layer). Your high-level managers can depend directly on `ISymmetricCipher` without being bound to a concrete implementation. You can swap your entire encryption algorithm from AES to ChaCha20 with a single line of code, without rewriting your business logic.

## 📦 Automatic Cryptographic Envelopes
For symmetric ciphers and hybrid encryption, CryptoUtility automatically packages the encrypted payload, random nonce, and authentication tag into a serialized cryptographic envelope under the hood using `MemoryPack` (an ultra-fast binary serializer). You receive a single, ready-to-transmit byte array or Base64 string. During decryption, the envelope is parsed automatically.

## ♻️ Cached Instances
To completely avoid allocations, we provide a `<Algo>.Shared` cached instance.

This allows you to leverage instance-based APIs continuously without the overhead of instantiating new objects for every cryptographic operation.

## 🧣 Static Wrapper API
All of our instance APIs are also wrapped with a static API, allowing direct usage of your desired algoithm for brevity, and convenience.

## 🗺️ One API, Every Implementation
Instead of learning a dozen distinct libraries, paradigms, and syntax patterns for different cryptographic requirements, you only need to learn CryptoUtility. As the project grows, it will continue to expand into a rich ecosystem of supported algorithms and third-party wrappers, giving you a singular, unified gateway to the entire modern cryptographic landscape.

---

# ✨ Features

* **Unified API Design**: Identical syntax patterns for encryption, decryption, signatures, key agreement, and hashing.
* **Built-in Utilities**: Out-of-the-box helper methods for seamless **Base64 string operations** and **easy key generation** using `Cipher.GenerateKey()`.
* **Symmetric Encryption (AEAD)**: Modern standards including **AES-256-GCM**, **AES-192-GCM**, **AES-128-GCM**, **ChaCha20-Poly1305**, and more.
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
var (encSuccess, envelope) = Rsa4096.HybridEncryptBase64(Aes256Gcm.Shared, publicKey, largePayload);

// Decrypt payload using the PRIVATE key
var (decSuccess, decryptedPayload) = Rsa4096.HybridDecryptBase64(Aes256Gcm.Shared, privateKey, envelope);
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
var (_, ciphertext) = Ecdh.Encrypt(Aes256Gcm.Shared, Hkdf.Shared, aliceSecret, "Hi Bob!", kdfSalt, kdfInfo);
var (_, decrypted) = Ecdh.Decrypt(Aes256Gcm.Shared, Hkdf.Shared, bobSecret, ciphertext, kdfSalt, kdfInfo);
```

---

# 📚 Cryptography API Reference

## Symmetric Encryption (AEAD — Recommended)

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|------|
| Aes256Gcm | .NET Built-in / BouncyCastle | CryptoUtility / CryptoUtility.BouncyCastle | Industry standard. |
| Aes192Gcm | .NET Built-in / BouncyCastle| CryptoUtility / CryptoUtility.BouncyCastle | Lower key size variant. |
| Aes128Gcm | .NET Built-in / BouncyCastle | CryptoUtility / CryptoUtility.BouncyCastle | Fast, widely supported. |
| ChaCha20Poly1305 | .NET Built-in / NaCl.Core | CryptoUtility / CryptoUtility.NaCl | Strong, efficient on software-only systems |
| XChaCha20Poly1305 | NaCl.Core | CryptoUtility.NaCl | Extended nonce variant, safer nonce handling |

---

## Symmetric Encryption (Non-AEAD)

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|----------------|
| Salsa20 | NaCl.Core | CryptoUtility.NaCl | No authentication |
| ChaCha20 | NaCl.Core | CryptoUtility.NaCl | No authentication |
| XChaCha20 | NaCl.Core | CryptoUtility.NaCl | No authentication |
| XorCipher | Custom | CryptoUtility.Extras | Obfuscation only, not secure |

---

## Asymmetric Encryption

| Algorithm  | Implementation | Package |  Notes |
|------------|----------------|----------|----------|
| Rsa1024 | .NET Built-in | CryptoUtility | Not secure |
| Rsa2048 | .NET Built-in | CryptoUtility | Minimum acceptable |
| Rsa3072 | .NET Built-in | CryptoUtility | Recommended |
| Rsa4096 | .NET Built-in | CryptoUtility | High cost, high security margin |

---

## Digital Signatures

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|------|
| Ecdsa | .NET Built-in | CryptoUtility | Message integrity & authentication |

---

## Key Agreement

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|--------|
| Ecdh | .NET Built-in | CryptoUtility | Shared secret derivation |

---

## Key Derivation Functions

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|------|
| Hkdf | .NET Built-in / HKDF.Standard | CryptoUtility / CryptoUtility.HkdfStandard | Standard key expansion. |

---

## Password Based Key Derivation Functions

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|------|
| Pbkdf2 | .NET Built-in | CryptoUtility | Password-based key derivation |

---

## Hashing & Checksums

### Cryptographic Hashes

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|------|
| Sha256 | .NET Built-in | CryptoUtility | Secure hash function |
| Sha384 | .NET Built-in | CryptoUtility | Secure hash function |
| Sha512 | .NET Built-in | CryptoUtility | Secure hash function |
| Sha3_256 | .NET Built-in | CryptoUtility | Modern SHA-3 variant |
| Sha3_384 | .NET Built-in | CryptoUtility | Modern SHA-3 variant |
| Sha3_512 | .NET Built-in | CryptoUtility | Modern SHA-3 variant |
| Sha1 | .NET Built-in | CryptoUtility | Deprecated, insecure |

---

### Non-Cryptographic Hashes / Checksums

| Algorithm | Implementation | Package | Notes |
|------------|----------------|----------|------|
| Crc32 | System.IO.Hashing | CryptoUtility.Extras | Integrity check only |
| Crc64 | System.IO.Hashing | CryptoUtility.Extras | Integrity check only |
| XxHash32 | System.IO.Hashing | CryptoUtility.Extras | High-speed hashing |
| XxHash64 | System.IO.Hashing | CryptoUtility.Extras | High-speed hashing |
| XxHash128 | System.IO.Hashing | CryptoUtility.Extras | High-speed hashing |

---

## 📝 API Notes

Official .NET implementations are recommended, as they are usually hardware accelerated, and have the best support, but they typically have less platform support, which is important if your on an older version of .NET; such as Unity developers, in those cases consider BouncyCastle or a purpose specific library that offers the implementation you need.

Over time the goal of this library is to support and unify all the popular cryptographic concepts and implementations.

---

## 🎭 Disambiguation

To maintain API brevity, this library has opted for all algorithm classes to use the same name, and are intended to be disambiguated through namespaces, and namespace aliases.

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
