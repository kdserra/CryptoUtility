# 🔐 CryptoUtility

[![NuGet Version](https://img.shields.io/badge/nuget-v0.26.1-blue.svg)](https://www.nuget.org/packages/CryptoUtility)
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
We define clean, unified interfaces like `ISymmetricCipher`, `IAsymmetricCipher`, `IKeyEncapsulationMechanism`, `IKeyAgreement`, `IDigitalSignature`, `IPasswordHasher`, `IChecksumProvider`, `IHashProvider`, `IMacProvider`, `IKeyExpansionKdf`, and `IPasswordKdf`.

This is incredibly powerful for building modular application systems (such as a `SaveManager` or a networking layer). Your high-level managers can depend directly on `ISymmetricCipher` without being bound to a concrete implementation. You can swap your entire encryption algorithm from AES to ChaCha20 with a single line of code, without rewriting your business logic.

## 📦 Automatic Encrypted and Decrypted Payload Formatting
For symmetric ciphers and hybrid encryption, CryptoUtility automatically packages the encrypted payload, random nonce, and authentication tag into a raw binary format under the hood (zero-overhead, no external serialization dependencies).

You receive a single, ready-to-transmit encrypted byte array or Base64 string. During decryption, the encrypted data is parsed and decrypted automatically.

## ♻️ Cached Instances
To completely avoid allocations, we provide a `<Algo>.Shared` cached instance.

This allows you to leverage instance-based APIs continuously without the overhead of instantiating new objects for every cryptographic operation.

## 🧣 Static Wrapper API
All of our instance APIs are also wrapped with a static API, allowing direct usage of your desired algoithm for brevity, and convenience.

## 🗺️ One API, Every Implementation
Instead of learning a dozen distinct libraries, paradigms, and syntax patterns for different cryptographic requirements, you only need to learn CryptoUtility. As the project grows, it will continue to expand into a rich ecosystem of supported algorithms and third-party wrappers, giving you a singular, unified gateway to the entire modern cryptographic landscape.

# ✨ Features

* **Unified API Design**: Identical syntax patterns for encryption, decryption, signatures, key agreement, hashing, and encapsulation.
* **Built-in Utilities**: Out-of-the-box helper methods for seamless **Base64 string operations**, **easy key generation** using `Cipher.GenerateKey()`, and backwards compatible cryptographic operations.
* **Symmetric Encryption (AEAD)**: Modern standards including **AES-256-GCM**, **ChaCha20-Poly1305**, and more.
* **Hybrid Encryption**: Encrypt large payloads easily using RSA public keys combined with the speed of AES-256-GCM under the hood.
* **Asymmetric & Signatures**: Full support for **RSA**, and elliptic curve digital signatures (**ECDSA**).
* **Post-Quantum Cryptography (PQC)**: Modern quantum-resistant algorithms for key encapsulation (**ML-KEM**, **BIKE**, **HQC**) and signatures (**ML-DSA**, **SLH-DSA**, **FALCON**).
* **Key Agreement & KEM**: Establish secure session keys over open channels using **ECDH** or post-quantum KEMs.
* **Hashing, Checksums & Password Storage**: SHA-2/3, Blake2/3, SM3, variable-length SHAKE, fast integrity check checksums (**CRC-32/64**, **xxHash32/64/128**), and standard PHC password storage hashing (**Argon2**, **Scrypt**, **Bcrypt**, **PBKDF2**).
* **MAC Providers**: Verify against message tampering by generating a Message Authentication Code (MAC) (including Blake Keyed MACs, HmacSM3, KMAC, GMAC, and Poly1305) and verifying it against the incoming message.

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

// Expand key to 32 bytes using secure defaults
byte[] expandedKey = Hkdf.DeriveKey(inputKeyMaterial, outputLength: 32, salt, info);
```

### 🔒 Password-Based Key Derivation (PBKDF2)
```csharp
using CryptoUtility.System;

string password = "UserPassword123!";
byte[] salt = "user-specific-salt"u8.ToArray();

// Derive a 32-byte key using secure defaults
byte[] derivedKey = Pbkdf2.DeriveKey(password, salt, outputLength: 32);
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

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| Aes256Gcm | CryptoUtility.System / CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | Advanced Encryption Standard in Galois/Counter Mode with a 256-bit key. It provides high-speed authenticated encryption with hardware support on most modern CPUs. |
| Aes192Gcm | CryptoUtility.System / CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | AES in Galois/Counter Mode with a 192-bit key size. |
| Aes128Gcm | CryptoUtility.System / CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | AES in Galois/Counter Mode with a 128-bit key size. |
| Aria256Gcm | CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | South Korean standard block cipher using a 256-bit key in Galois/Counter Mode. It is widely used in South Korean government and financial sectors. |
| Aria192Gcm | CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | ARIA block cipher in Galois/Counter Mode with a 192-bit key size. |
| Aria128Gcm | CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | ARIA block cipher in Galois/Counter Mode with a 128-bit key size. |
| Camellia256Gcm | CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | Japanese/European standard block cipher using a 256-bit key in Galois/Counter Mode. It provides security and performance comparable to AES. |
| Camellia192Gcm | CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | Camellia block cipher in Galois/Counter Mode with a 192-bit key size. |
| Camellia128Gcm | CryptoUtility.BouncyCastle | ISymmetricCipherAEAD | Camellia block cipher in Galois/Counter Mode with a 128-bit key size. |
| ChaCha20Poly1305 | CryptoUtility.System / CryptoUtility.BouncyCastle / CryptoUtility.NaCl | ISymmetricCipherAEAD | A high-performance authenticated encryption algorithm combining the ChaCha20 stream cipher and Poly1305 authenticator. It is exceptionally fast in software-only environments, making it preferred for mobile devices without AES hardware acceleration. |
| XChaCha20Poly1305 | CryptoUtility.NaCl | ISymmetricCipherAEAD | A variant of ChaCha20Poly1305 that uses an extended 192-bit nonce, allowing safe random nonce generation in stateless or highly distributed systems. |

## Symmetric Encryption (Non-AEAD)

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|----------------|
| Salsa20 | CryptoUtility.NaCl | ISymmetricCipher | A high-speed stream cipher designed by Daniel J. Bernstein. It does not provide built-in authentication. |
| ChaCha20 | CryptoUtility.NaCl | ISymmetricCipher | A faster, improved variant of Salsa20. It does not provide built-in authentication. |
| XChaCha20 | CryptoUtility.NaCl | ISymmetricCipher | A variant of ChaCha20 using an extended 192-bit nonce. It does not provide built-in authentication. |
| XorCipher | CryptoUtility.Extras | ISymmetricCipher | A basic XOR obfuscation cipher. Intended only for testing or simple data obfuscation as it does not offer cryptographic security. |

## Asymmetric & Hybrid Encryption

| Algorithm  | Package | Interfaces | Notes |
|------------|----------|------------|----------|
| Rsa1024 | CryptoUtility.System / CryptoUtility.BouncyCastle | IAsymmetricCipher | Legacy RSA asymmetric algorithm. Cryptographically insecure for modern systems due to small key size. |
| Rsa2048 | CryptoUtility.System / CryptoUtility.BouncyCastle | IAsymmetricCipher | RSA asymmetric algorithm. The minimum acceptable key size for legacy systems. |
| Rsa3072 | CryptoUtility.System / CryptoUtility.BouncyCastle | IAsymmetricCipher | RSA asymmetric algorithm. The recommended key size for new, secure asymmetric key transport. |
| Rsa4096 | CryptoUtility.System / CryptoUtility.BouncyCastle | IAsymmetricCipher | RSA asymmetric algorithm. High security margin with higher computational overhead. |

## Post-Quantum Key Encapsulation Mechanisms (KEM)

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| MlKem768 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | Module-Lattice-Based Key Encapsulation Mechanism (FIPS 203 standardized). Standard quantum-resistant key establishment at FIPS security category 3. |
| MlKem1024 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | Module-Lattice-Based Key Encapsulation Mechanism (FIPS 203 standardized). Standard quantum-resistant key establishment at FIPS security category 5. |
| Bike128 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | Bit-Flipping Key Encapsulation. A code-based post-quantum KEM secure against quantum computer brute-forcing at 128-bit security level. |
| Bike192 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | BIKE key encapsulation at 192-bit security level. |
| Bike256 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | BIKE key encapsulation at 256-bit security level. |
| Hqc128 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | Hamming Quasi-Cyclic KEM. A code-based post-quantum key encapsulation algorithm secure against quantum computers at 128-bit security level. |
| Hqc192 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | HQC key encapsulation at 192-bit security level. |
| Hqc256 | CryptoUtility.BouncyCastle | IKeyEncapsulationMechanism | HQC key encapsulation at 256-bit security level. |

## Digital Signatures

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| Ecdsa | CryptoUtility.System / CryptoUtility.BouncyCastle | IDigitalSignature | Elliptic Curve Digital Signature Algorithm. Provides secure signatures with smaller keys and signatures than RSA. |
| MlDsa44 | CryptoUtility.BouncyCastle | IDigitalSignature | Module-Lattice-Based Digital Signature Algorithm (FIPS 204 standardized). Standardized quantum-resistant signature scheme at FIPS security category 2. |
| MlDsa65 | CryptoUtility.BouncyCastle | IDigitalSignature | ML-DSA digital signatures at FIPS security category 3. |
| MlDsa87 | CryptoUtility.BouncyCastle | IDigitalSignature | ML-DSA digital signatures at FIPS security category 5. |
| SlhDsa128f | CryptoUtility.BouncyCastle | IDigitalSignature | Stateless Hash-Based Digital Signature Algorithm (FIPS 205 standardized). Highly conservative PQC signature using fast-signing parameter sets at 128-bit security level. |
| SlhDsa128s | CryptoUtility.BouncyCastle | IDigitalSignature | SLH-DSA signatures using small-signature parameter sets at 128-bit security level. |
| SlhDsa192f | CryptoUtility.BouncyCastle | IDigitalSignature | SLH-DSA signatures using fast-signing parameter sets at 192-bit security level. |
| SlhDsa192s | CryptoUtility.BouncyCastle | IDigitalSignature | SLH-DSA signatures using small-signature parameter sets at 192-bit security level. |
| SlhDsa256f | CryptoUtility.BouncyCastle | IDigitalSignature | SLH-DSA signatures using fast-signing parameter sets at 256-bit security level. |
| SlhDsa256s | CryptoUtility.BouncyCastle | IDigitalSignature | SLH-DSA signatures using small-signature parameter sets at 256-bit security level. |
| Falcon512 | CryptoUtility.BouncyCastle | IDigitalSignature | Lattice-based post-quantum digital signatures based on NTRU lattices. Small signature size and very fast verification. |
| Falcon1024 | CryptoUtility.BouncyCastle | IDigitalSignature | Falcon lattice-based signatures with high security margin. |

## Key Agreement

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|--------|
| Ecdh | CryptoUtility.System / CryptoUtility.BouncyCastle | IKeyAgreement | Elliptic Curve Diffie-Hellman key agreement. Establish shared secrets over public networks. |

## Key Derivation Functions

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| Hkdf | CryptoUtility.System / CryptoUtility.BouncyCastle / CryptoUtility.HkdfStandard | IKeyExpansionKdf | HMAC-based Extract-and-Expand Key Derivation Function. Securely derives multiple cryptographically strong subkeys from master secrets. |

## Password Hashing & Key Derivation (PHC Storage)

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| Argon2id | CryptoUtility.BouncyCastle | IPasswordHasher, IPasswordKdf | Recommended password hashing function (winner of the Password Hashing Competition). Combines defense against GPU cracking and side-channel attacks. |
| Argon2i | CryptoUtility.BouncyCastle | IPasswordHasher, IPasswordKdf | Argon2 optimized for resistance to side-channel timing attacks. |
| Argon2d | CryptoUtility.BouncyCastle | IPasswordHasher, IPasswordKdf | Argon2 optimized for maximum memory-hardness to prevent GPU attacks. |
| Scrypt | CryptoUtility.BouncyCastle | IPasswordHasher, IPasswordKdf | Memory-hard password hashing function. Resistant to hardware brute-forcing via customized ASICs. |
| Bcrypt | CryptoUtility.BouncyCastle | IPasswordHasher | CPU-hard work factor password hashing algorithm, incorporating a cost parameter to scale with hardware improvements. |
| Pbkdf2 | CryptoUtility.System / CryptoUtility.BouncyCastle | IPasswordHasher, IPasswordKdf | Standard password key derivation, widely supported for legacy and cross-platform compatibility. |

## Hashing & Checksums

### Cryptographic Hashes

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| Sha256 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Standard secure hash function producing a 256-bit digest. |
| Sha384 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Standard secure hash function producing a 384-bit digest. |
| Sha512 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Standard secure hash function producing a 512-bit digest. |
| Sha3_256 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Modern SHA-3 hash function based on the Keccak sponge construction, producing a 256-bit digest. |
| Sha3_384 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Modern SHA-3 hash function producing a 384-bit digest. |
| Sha3_512 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Modern SHA-3 hash function producing a 512-bit digest. |
| Blake2b | CryptoUtility.BouncyCastle | IHashProvider | High-speed cryptographic hash optimized for 64-bit platforms. |
| Blake2s | CryptoUtility.BouncyCastle | IHashProvider | High-speed cryptographic hash optimized for 8/16/32-bit platforms. |
| Blake3 | CryptoUtility.BouncyCastle | IHashProvider | Extremely fast cryptographic hash using a Merkle tree structure to parallelize across multi-core processors. |
| SM3 | CryptoUtility.BouncyCastle | IHashProvider | Cryptographic hash function standardized by the Chinese government (GM/T 0004-2012) for secure commercial hashing. |
| Shake128 | CryptoUtility.BouncyCastle | IHashProvider | Extendable-Output Function (XOF) from the SHA-3 family, allowing variable-length output digests. |
| Shake256 | CryptoUtility.BouncyCastle | IHashProvider | Extendable-Output Function (XOF) allowing variable-length output digests with higher security margin. |
| Ripemd160 | CryptoUtility.BouncyCastle | IHashProvider | 160-bit cryptographic hash function, primarily used for legacy compatibility (e.g. Bitcoin address generation). |
| Whirlpool | CryptoUtility.BouncyCastle | IHashProvider | 512-bit cryptographic hash function based on a modified AES block cipher structure. |
| Sha1 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Legacy hash function. Insecure for secure applications. |
| Md5 | CryptoUtility.System / CryptoUtility.BouncyCastle | IHashProvider | Legacy hash function. Insecure for secure applications. |

### Non-Cryptographic Checksums (`IChecksumProvider`)

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| Crc32 | CryptoUtility.System.Extras | IChecksumProvider | Fast non-cryptographic Cyclic Redundancy Check checksum to detect accidental data corruption or transmission errors. |
| Crc64 | CryptoUtility.System.Extras | IChecksumProvider | Fast non-cryptographic Cyclic Redundancy Check checksum with 64-bit output size. |
| XxHash32 | CryptoUtility.System.Extras | IChecksumProvider | Extremely fast non-cryptographic hash running near RAM speed limits, producing 32-bit output. |
| XxHash64 | CryptoUtility.System.Extras | IChecksumProvider | Extremely fast non-cryptographic hash producing 64-bit output. |
| XxHash128 | CryptoUtility.System.Extras | IChecksumProvider | Extremely fast non-cryptographic hash producing 128-bit output. |

### Message Authentication Code (MAC)

| Algorithm | Package | Interfaces | Notes |
|------------|----------|------------|------|
| HmacSha256 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Hash-based Message Authentication Code using the SHA-256 hash. |
| HmacSha384 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Hash-based Message Authentication Code using the SHA-384 hash. |
| HmacSha512 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Hash-based Message Authentication Code using the SHA-512 hash. |
| HmacSha3_256 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Hash-based Message Authentication Code using the SHA3-256 hash. |
| HmacSha3_384 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Hash-based Message Authentication Code using the SHA3-384 hash. |
| HmacSha3_512 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Hash-based Message Authentication Code using the SHA3-512 hash. |
| HmacSM3 | CryptoUtility.BouncyCastle | IMacProvider | Message authentication code utilizing the Chinese standard SM3 hash function. |
| Blake2bMac | CryptoUtility.BouncyCastle | IMacProvider | Keyed MAC mode utilizing Blake2b hashing, avoiding double-hash overhead. |
| Blake2sMac | CryptoUtility.BouncyCastle | IMacProvider | Keyed MAC mode utilizing Blake2s hashing. |
| Blake3Mac | CryptoUtility.BouncyCastle | IMacProvider | Keyed MAC mode utilizing Blake3 hashing. |
| Kmac128 | CryptoUtility.BouncyCastle | IMacProvider | Keccak-based Message Authentication Code standardized under NIST SP 800-185. |
| Kmac256 | CryptoUtility.BouncyCastle | IMacProvider | Keccak-based Message Authentication Code with higher security margin. |
| GMAC | CryptoUtility.BouncyCastle | IMacProvider | Galois Message Authentication Code. Fast AES-GCM MAC mode returning `[Nonce][Tag]`. |
| Poly1305 | CryptoUtility.BouncyCastle / CryptoUtility.NaCl | IMacProvider | A fast, secure one-time authenticator. It takes a 32-byte key and a nonce to produce a 16-byte authentication tag, returning `[Nonce][Tag]`. |
| HmacSha1 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Legacy message authentication code. |
| HmacMd5 | CryptoUtility.System / CryptoUtility.BouncyCastle | IMacProvider | Legacy message authentication code. |

---

## 📦 Raw Binary Formats & Password Storage Formats

CryptoUtility provides consistent raw byte structures across all packages for seamless integration:

### 1. Symmetric Encryption Layouts

#### AEAD Ciphers (AES-GCM, ARIA-GCM, Camellia-GCM, ChaCha20-Poly1305)
```
+-------------------+-----------------------------+-----------------------+
|   Nonce (N bytes) |   Ciphertext (C bytes)      |  Auth Tag (T bytes)   |
+-------------------+-----------------------------+-----------------------+
```

#### Non-AEAD Ciphers (ChaCha20, Salsa20, XOR Obfuscation)
```
+-------------------+-----------------------------+
|   Nonce (N bytes) |   Ciphertext (C bytes)      |
+-------------------+-----------------------------+
```

### 2. Hybrid Asymmetric Encryption Layout
```
+---------------------------------+------------------------+------------------------+
| AsymEncrypted Length (4 bytes)  | AsymEncrypted Payload  | SymEncrypted Payload   |
+---------------------------------+------------------------+------------------------+
```

### 3. Nonce-Based MAC Tag Layout (GMAC, Poly1305)
```
+-------------------+-----------------------------+
|   Nonce (N bytes) |   Auth Tag (T bytes)        |
+-------------------+-----------------------------+
```

### 4. Password Hashing PHC Formats

CryptoUtility formats hashed passwords into standard PHC strings for database storage:

*   **Argon2 (d/i/id)**: `$argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt-base64>$<hash-base64>`
*   **Scrypt**: `$scrypt$ln=<N>,r=<r>,p=<p>$<salt-base64>$<hash-base64>`
*   **Bcrypt**: Standard Modular Crypt Format (e.g. `$2b$<cost>$<salt><hash>`)
*   **PBKDF2**: `$pbkdf2-sha256$i=<iterations>$<salt-base64>$<hash-base64>`

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
