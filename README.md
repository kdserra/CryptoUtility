# CryptoUtility

Cryptography, made simple.

Everybody ends up wrapping cryptography to a simpler usability-focused API.  This library focuses purely on making the developer experience easier by standardizing the usage of APIs to simplify the usage of cryptography so you can focus on doing what you care about.

CryptoUtility does not implement the cipher, it wraps them -- the same way your own cryptography helper classes do.

This means all ciphers are simplified and unified under a single API.  If you know how to encrypt using any algo, you know how to using all of them.  Of course, there are some optional features you can utilize by learning the individual quirks, but generally speaking it's usage is simplified from a developer perspective, without sacrificing on security.

This means we support multiple implementations for the same cipher.  This sounds bad, but it's actually a good thing; some benefit from hardware intrinsic acceleration due to being native, at the cost of platform support (which you might care about if your a game developer targetting consoles)

The only exception to this is non-standard popular ciphers like the Xor Cipher.  Of course, it's not reccomended to use the XorCipher as it has no authenticated tag, but I provided it due to it's popularity.

The long term goal of this project is to support all the popular symmetric ciphers, asymmetric ciphers, hash algos, key agreement implementations, and anything else that benefits from being wrapped behind a unified API.

## How it works

**Q:** How are the ciphers standardized despite ciphers being non-standard?
	- Stateless doesn't require nonce
	- AE additionally requires auth tag
	- AEAD additionally requires AAD

**A:** The simple `Encrypt(key, plaintext)` will generate the necessary fields for you (the nonce, compute the tag if AE/AEAD), and we wrap the ciphertext with our crypto envelope that adds metadata to track ex: the nonce, and tag for you.  This means you no longer need to provide those parameters and they will still get used.  When you decrypt, we parse out the nonce/tag automatically and use it to decrypt the message.  This makes the API usage simple, while retaining the enhanced security of more complex usage authenticated ciphers.  You can still  pass your own nonce/aad if you prefer.  Tags are never passed in because they are always computed authentication codes by the authentication cipher.

Our crypto envelopes are serialized using the MemoryPack binary serializer.

## Usage

The simple workflow is:
- Generate a key: `*Cipher*.GenerateKey();`
- Encrypt: `*Cipher*.Encrypt(key, plaintext);`
- Decrypt: `*Cipher*.Decrypt(key, encrypted);`

Base64 string workflow:
- Generate a key: `*Cipher*.GenerateKeyBase64();`
- Encrypt: `*Cipher*.EncryptBase64(key, plaintext);`
- Decrypt: `*Cipher*.DecryptBase64(key, encrypted);`

You can also provide a nonce.

**Encrypt/Decrypt Round Trip using Byte Arrays:**
```csharp
byte[] key = Aes256Gcm.GenerateKey();
byte[] plaintext = Encoding.UTF8.GetBytes("Hello, World!");

(bool success, byte[] encrypted) encryptionResult = Aes256Gcm.Encrypt(key, plaintext);
if (!encryptionResult.success)
{
    // Encryption failed, this will occur if you used an invalid key, nonce, etc.
    return;
}

(bool success, byte[] decryptedPlaintext) decryptionResult = Aes256Gcm.Decrypt(
    key,
    encryptionResult.encrypted
);
if (!decryptionResult.success)
{
    // Decryption failed, this will occur if you used an invalid key, ciphertext, nonce, auth tag, aad, etc.
    return;
}

// plaintext and decryptedPlaintext are the same.
Console.WriteLine("Original plaintext: " + Encoding.UTF8.GetString(plaintext));
Console.WriteLine("Decrypted plaintext: " + Encoding.UTF8.GetString(decryptionResult.decryptedPlaintext));
```

**Encrypt/Decrypt Round Trip using Base64 Strings:**
```csharp

```


## Symmetric Ciphers

Symmetric Ciphers use a key to encrypt a plaintext into a ciphertext.

### System
- AES 128 GCM
- AES 192 GCM
- AES 256 GCM

### Custom
- XOR Cipher
