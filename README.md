# 🔐 CryptoUtility

[![NuGet Version](https://img.shields.io/badge/nuget-v0.24.3-blue.svg)](https://www.nuget.org/packages/CryptoUtility)
[![Target Framework](https://img.shields.io/badge/.NET-Standard%202.1%20|%208.0%20|%2010.0-green.svg)](https://dotnet.microsoft.com)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/kdserra/CryptoUtility/blob/master/LICENSE.md)
[![Build Status](https://img.shields.io/github/actions/workflow/status/kdserra/CryptoUtility/builder.yml?branch=master)](https://github.com/kdserra/CryptoUtility/actions/workflows/builder.yml)

> **Cryptography, Simplified & Unified.**  
> A developer-first cryptography abstraction library for .NET. Secure your data with state-of-the-art ciphers using a single, unified interface.

# ❓ Why CryptoUtility?
CryptoUtility makes it quick, simple, and easy to work with cryptography.

We provide commonly requested utilities like Base64 support, easy key generation, unified interfaces that make it easy to swap implementations, or abstract dependencies, and provide backwards compatible implementations for common cryptographic operations.

CryptoUtility enables access to an entire ecosystem; no longer requiring you to learn different crypto APIs for different libraries.  In our library, using an authenticated cipher is just as simple and easy as a stateless cipher.  You no longer have to manage `IDisposable` objects and risk memory leaks as our wrappers deal with them.

This keeps your focus where it belongs: writing your application.

## ⚡ State-of-the-Art Security, Simple APIs
With CryptoUtility, executing high-security authenticated encryption (AEAD) like **AES-256-GCM** or **ChaCha20-Poly1305** is just as straightforward as running a stateless cipher. All complex logic—such as secure nonce generation, authentication tag handling, and associated data verification—is managed automatically.

## 🧩 Unified Interfaces
We define clean, unified interfaces like `ISymmetricCipher`, `IAsymmetricCipher`, `IKeyAgreement`, `IDigitalSignature`, `IHashProvider`, `IMacProvider`, `IKeyExpansionKdf`, and `IPasswordKdf`.

This is incredibly powerful for building modular application systems (such as a `SaveManager` or a networking layer). Your high-level managers can depend directly on `ISymmetricCipher` without being bound to a concrete implementation. You can swap your entire encryption algorithm from AES to ChaCha20 with a single line of code, without rewriting your business logic.

## 📦 Automatic Encrypted and Decrypted Payload Formatting
For symmetric ciphers and hybrid encryption, CryptoUtility automatically packages the encrypted payload, random nonce, and authentication tag into a unified format under the hood using `MemoryPack` (an ultra-fast binary serializer). You receive a single, ready-to-transmit encrypted byte array or Base64 string. During decryption, the encrypted data is parsed and decrypted automatically.

## ♻️ Cached Instances
To completely avoid allocations, we provide a `<Algo>.Shared` cached instance.

This allows you to leverage instance-based APIs continuously without the overhead of instantiating new objects for every cryptographic operation.

## 🧣 Static Wrapper API
All of our instance APIs are also wrapped with a static API, allowing direct usage of your desired algoithm for brevity, and convenience.

## 🗺️ One API, Every Implementation
Instead of learning a dozen distinct libraries, paradigms, and syntax patterns for different cryptographic requirements, you only need to learn CryptoUtility. As the project grows, it will continue to expand into a rich ecosystem of supported algorithms and third-party wrappers, giving you a singular, unified gateway to the entire modern cryptographic landscape.

# ✨ Features

* **Unified API Design**: Identical syntax patterns for encryption, decryption, signatures, key agreement, and hashing.
* **Built-in Utilities**: Out-of-the-box helper methods for seamless **Base64 string operations**, **easy key generation** using `Cipher.GenerateKey()`, and backwards compatible cryptograhpic operations.
* **Symmetric Encryption (AEAD)**: Modern standards including **AES-256-GCM**, **ChaCha20-Poly1305**, and more.
* **Hybrid Encryption**: Encrypt large payloads easily using RSA public keys combined with the speed of AES-256-GCM under the hood.
* **Asymmetric & Signatures**: Full support for **RSA**, and elliptic curve digital signatures (**ECDSA**).
* **Key Agreement**: Establish secure session keys over open channels using **ECDH**.
* **Hashing & Checksums**: SHA-2/3, fast non-cryptographic hashes **(xxHash32/64/128)**, and integrity checksums **(CRC-32, CRC-64)**.
* **MAC Providers**: Verify against message tampering by generating a Message Authentication Code (MAC) and verifying it against the incoming message.

# 🚀 Getting Started

All primary APIs return direct values and bubble up exceptions natively if an error occurs. 

## 1️⃣ Symmetric Encryption (AES-256-GCM)

### 🔤 Base64 String Workflow
```csharp
using CryptoUtility.System;

// 1. Generate a secure, random key as a Base64 string
string base64Key = Aes256Gcm.GenerateKeyBase64();

// 2. Encrypt plaintext directly into a self-contained Base64 string
string plaintext = "Confidential customer details...";
string encrypted = Aes256Gcm.EncryptBase64(base64Key, plaintext);

// 3. Decrypt with a single call directly to value
string decryptedText = Aes256Gcm.DecryptBase64(base64Key, encrypted);
Console.WriteLine($"Decrypted: {decryptedText}"); // Confidential customer details...
```

### 📦 Byte Array Workflow
```csharp
using CryptoUtility.System;

// 1. Generate key and plaintext bytes
byte[] key = Aes256Gcm.GenerateKey();
byte[] plaintext = "Hello World"u8.ToArray();

// 2. Encrypt and Decrypt directly
byte[] encrypted = Aes256Gcm.Encrypt(key, plaintext);
byte[] decrypted = Aes256Gcm.Decrypt(key, encrypted);
```

## 2️⃣ Asymmetric Encryption/Decryption (RSA-4096)

```csharp
using CryptoUtility.System;

// 1. Generate an RSA KeyPair
var (publicKey, privateKey) = Rsa4096.GenerateKeyPair();

// 2. Encrypt plaintext with the public key
byte[] plaintext = "Secret message"u8.ToArray();
byte[] encrypted = Rsa4096.Encrypt(publicKey, plaintext);

// 3. Decrypt ciphertext with the private key
byte[] decrypted = Rsa4096.Decrypt(privateKey, encrypted);
```

## 3️⃣ Hybrid Asymmetric Encryption (RSA-4096 + AES)

```csharp
using CryptoUtility.System;

// Generate public/private keypair
var (publicKey, privateKey) = Rsa4096.GenerateKeyPairBase64();

// Encrypt payload using the PUBLIC key
string largePayload = "Highly confidential PDF database dump...";
string encrypted = Rsa4096.HybridEncryptBase64(Aes256Gcm.Shared, publicKey, largePayload);

// Decrypt payload using the PRIVATE key
string decrypted = Rsa4096.HybridDecryptBase64(Aes256Gcm.Shared, privateKey, encrypted);
```

## 4️⃣ Digital Signatures (ECDSA)

```csharp
using CryptoUtility.System;

// 1. Generate an ECDSA KeyPair
var (publicKey, privateKey) = Ecdsa.GenerateKeyPair();

// 2. Sign message bytes with the private key
byte[] message = "Message to sign"u8.ToArray();
byte[] signature = Ecdsa.Sign(message, privateKey);

// 3. Verify signature with the public key
bool isValid = Ecdsa.Verify(message, signature, publicKey);
```

## 5️⃣ Key Agreement (ECDH)

```csharp
using CryptoUtility.System;

// 1. Establish KeyPairs for Alice and Bob
var (alicePub, alicePriv) = Ecdh.GenerateKeyPair();
var (bobPub, bobPriv) = Ecdh.GenerateKeyPair();

// 2. Alice and Bob derive the SAME shared secret
byte[] aliceSecret = Ecdh.DeriveSharedSecret(alicePriv, bobPub);
byte[] bobSecret = Ecdh.DeriveSharedSecret(bobPriv, alicePub);

// 3. Configure KDF parameters for session security
byte[] kdfSalt = "session-salt"u8.ToArray();
byte[] kdfInfo = "session-context-info"u8.ToArray();

// 4. Encrypt and Decrypt using derived secrets
byte[] encrypted = Ecdh.Encrypt(Aes256Gcm.Shared, Hkdf.Shared, aliceSecret, "Hi Bob!"u8.ToArray(), kdfSalt, kdfInfo);
byte[] decrypted = Ecdh.Decrypt(Aes256Gcm.Shared, Hkdf.Shared, bobSecret, encrypted, kdfSalt, kdfInfo);
```

## 6️⃣ Hashing & Checksums

```csharp
using CryptoUtility.System;

byte[] data = "Hash this string"u8.ToArray();

// Compute SHA-256 hash
byte[] hash = Sha256.Hash(data);

// Compute Base64 representation directly
string base64Hash = Sha256.HashBase64("Hash this string");
```

## 7️⃣ Message Authentication Code (HMAC-SHA256)

```csharp
using CryptoUtility.System;

// 1. Generate a random MAC key
string macKey = HmacSha256.GenerateKeyBase64();

// 2. Compute the MAC tag
string message = "Authenticate me";
string macTag = HmacSha256.ComputeMacBase64(macKey, message);

// 3. Verify the MAC tag
bool isValid = HmacSha256.VerifyBase64(macKey, message, macTag);
```

## 8️⃣ Key Derivation Functions (KDF)

### 🔑 Key Expansion (HKDF)
```csharp
using CryptoUtility.System;

byte[] inputKeyMaterial = "master-key-material"u8.ToArray();
byte[] salt = "hkdf-salt-example"u8.ToArray();
byte[] info = "application-context-example"u8.ToArray();

// Expand key to 32 bytes
byte[] expandedKey = Hkdf.DeriveKey(inputKeyMaterial, iterations: 1, outputLength: 32, salt, info);
```

### 🔒 Password-Based Key Derivation (PBKDF2)
```csharp
using CryptoUtility.System;

string password = "UserPassword123!";
byte[] salt = "user-specific-salt"u8.ToArray();

// Derive a 32-byte key using 100,000 iterations
byte[] derivedKey = Pbkdf2.DeriveKey(password, salt, iterations: 100000, outputLength: 32);
```

---

> [!NOTE]
> **Try Variant APIs**: For all direct-value throwing APIs, matching `Try` variant extension methods are available (e.g. `TryEncrypt`, `TryDecrypt`, `TryDeriveSharedSecret`). These catch exceptions internally, return `false` on failure, and return the output via an `out` parameter.
> For example:
> ```csharp
> if (Aes256Gcm.TryEncrypt(key, plaintext, out byte[] encrypted)) {
>     // Encryption succeeded
> }
> ```

# 🧪 Sample

View the [sample](https://github.com/kdserra/CryptoUtility/blob/master/CryptoUtility.Sample/Program.cs) to see all the features in use, you can also run the [pre-compiled sample binary](https://github.com/kdserra/CryptoUtility/releases) to see the execution results.

# 📚 Cryptography API Reference

## Symmetric Encryption (AEAD — Recommended)

| Algorithm | Package | Notes |
|------------|----------|------|
| Aes256Gcm | CryptoUtility.System / CryptoUtility.BouncyCastle | Industry standard. |
| Aes192Gcm | CryptoUtility.System / CryptoUtility.BouncyCastle | Lower key size variant. |
| Aes128Gcm | CryptoUtility.System / CryptoUtility.BouncyCastle | Fast, widely supported. |
| ChaCha20Poly1305 | CryptoUtility.System / CryptoUtility.BouncyCastle / CryptoUtility.NaCl | Strong, efficient on software-only systems |
| XChaCha20Poly1305 | CryptoUtility.NaCl | Extended nonce variant, safer nonce handling |

## Symmetric Encryption (Non-AEAD)

| Algorithm | Package | Notes |
|------------|----------|----------------|
| Salsa20 | CryptoUtility.NaCl | No authentication |
| ChaCha20 | CryptoUtility.NaCl | No authentication |
| XChaCha20 | CryptoUtility.NaCl | No authentication |
| XorCipher | CryptoUtility.Extras | Obfuscation only, not secure |

## Asymmetric Encryption

| Algorithm  | Package |  Notes |
|------------|----------|----------|
| Rsa1024 | CryptoUtility.System / CryptoUtility.BouncyCastle | Not secure |
| Rsa2048 | CryptoUtility.System / CryptoUtility.BouncyCastle | Minimum acceptable |
| Rsa3072 | CryptoUtility.System / CryptoUtility.BouncyCastle | Recommended |
| Rsa4096 | CryptoUtility.System / CryptoUtility.BouncyCastle | High cost, high security margin |

## Digital Signatures

| Algorithm | Package | Notes |
|------------|----------|------|
| Ecdsa | CryptoUtility.System / CryptoUtility.BouncyCastle | Message integrity & authentication |

## Key Agreement

| Algorithm | Package | Notes |
|------------|----------|--------|
| Ecdh | CryptoUtility.System / CryptoUtility.BouncyCastle | Shared secret derivation |

## Key Derivation Functions

| Algorithm | Package | Notes |
|------------|----------|------|
| Hkdf | CryptoUtility.System / CryptoUtility.BouncyCastle / CryptoUtility.HkdfStandard | Standard key expansion. |

## Password Based Key Derivation Functions

| Algorithm | Package | Notes |
|------------|----------|------|
| Pbkdf2 | CryptoUtility.System / CryptoUtility.BouncyCastle | Password-based key derivation |

## Hashing & Checksums

### Cryptographic Hashes

| Algorithm | Package | Notes |
|------------|----------|------|
| Sha256 | CryptoUtility.System / CryptoUtility.BouncyCastle | Secure hash function |
| Sha384 | CryptoUtility.System / CryptoUtility.BouncyCastle | Secure hash function |
| Sha512 | CryptoUtility.System / CryptoUtility.BouncyCastle | Secure hash function |
| Sha3_256 | CryptoUtility.System / CryptoUtility.BouncyCastle | Modern SHA-3 variant |
| Sha3_384 | CryptoUtility.System / CryptoUtility.BouncyCastle | Modern SHA-3 variant |
| Sha3_512 | CryptoUtility.System / CryptoUtility.BouncyCastle | Modern SHA-3 variant |
| Sha1 | CryptoUtility.System / CryptoUtility.BouncyCastle | Insecure |
| Md5 | CryptoUtility.System / CryptoUtility.BouncyCastle | Insecure |

### Non-Cryptographic Hashes / Checksums

| Algorithm | Package | Notes |
|------------|----------|------|
| Crc32 | CryptoUtility.System.Extras | Integrity check only |
| Crc64 | CryptoUtility.System.Extras | Integrity check only |
| XxHash32 | CryptoUtility.System.Extras | High-speed hashing |
| XxHash64 | CryptoUtility.System.Extras | High-speed hashing |
| XxHash128 | CryptoUtility.System.Extras | High-speed hashing |

### Message Authentication Code

| Algorithm | Package | Notes |
|------------|----------|------|
| HmacSha256 | CryptoUtility.System / CryptoUtility.BouncyCastle | Secure hash function |
| HmacSha384 | CryptoUtility.System / CryptoUtility.BouncyCastle | Secure hash function |
| HmacSha512 | CryptoUtility.System / CryptoUtility.BouncyCastle | Secure hash function |
| HmacSha3_256 | CryptoUtility.System / CryptoUtility.BouncyCastle | Modern SHA-3 variant |
| HmacSha3_384 | CryptoUtility.System / CryptoUtility.BouncyCastle | Modern SHA-3 variant |
| HmacSha3_512 | CryptoUtility.System / CryptoUtility.BouncyCastle | Modern SHA-3 variant |
| HmacSha1 | CryptoUtility.System / CryptoUtility.BouncyCastle | Legacy |
| Poly1305 | CryptoUtility.BouncyCastle / CryptoUtility.NaCl | Fast, secure one-time MAC *(requires a unique key/nonce per message; often paired with ChaCha20)* |
| HmacMd5 | CryptoUtility.System / CryptoUtility.BouncyCastle | Insecure |

## 📝 API Notes

The core CryptoUtility package contains only the contracts, serialization models, and utilities.  The individual extension packages contain implementations built upon the core contracts.

Official .NET implementations are recommended, as they are usually hardware accelerated, and have the best support, but they typically have less platform support, which is important if your on an older version of .NET; such as Unity developers, in those cases consider BouncyCastle or a purpose specific library that offers the implementation you need.

Over time the goal of this library is to support and unify all the popular cryptographic concepts and implementations.

## 🗺️ Disambiguation

To maintain API brevity, this library has opted for all algorithm classes to use the same name, and are intended to be disambiguated through namespaces, and namespace aliases.

# 🛡️ Security Best Practices

* **No Static Nonces**: CryptoUtility generates a unique, cryptographically secure random nonce for every single symmetric encryption.
* **Authentication-First**: We default to AEAD (Authenticated Encryption with Associated Data) ciphers to prevent bit-flipping and padding oracle attacks.
* **Memory Sanitation**: Sensitive derived keys are zeroed out of system memory immediately after use.
* **Standard Implementations**: We do not roll custom cryptographic algorithms. We wrap standard, industry-vetted implementations, except where one is not available.

# 📦 Installation

Add the NuGet package to your project:

```bash
dotnet add package CryptoUtility
```

## 📜 Full package list:

- [CryptoUtility](https://www.nuget.org/packages/CryptoUtility)
- [CryptoUtility.System](https://www.nuget.org/packages/CryptoUtility.System)
- [CryptoUtility.System.Extras](https://www.nuget.org/packages/CryptoUtility.System.Extras)
- [CryptoUtility.BouncyCastle](https://www.nuget.org/packages/CryptoUtility.BouncyCastle)
- [CryptoUtility.HkdfStandard](https://www.nuget.org/packages/CryptoUtility.HkdfStandard)
- [CryptoUtility.NaCl](https://www.nuget.org/packages/CryptoUtility.NaCl)
- [CryptoUtility.Extras](https://www.nuget.org/packages/CryptoUtility.Extras)

# 📄 License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.
