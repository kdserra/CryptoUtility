namespace CryptoUtility.Tests;

public class Aes256GcmTests
{
    // MethodName_StateUnderTest_ExpectedBehavior

    [Fact]
    public void Encrypt_ValidKeyAndAutoNonce_ReturnsSuccessStateAndEncryptedBytes()
    {
        // Arrange
        string plaintextString = "Hello, World!";
        byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintextString);
        byte[] key = Aes256Gcm.GenerateKey();

        // Act
        (bool success, byte[] encrypted) encryptionResult = Aes256Gcm.Encrypt(key, plaintextBytes);

        // Assert
        Assert.True(encryptionResult.success);
        Assert.NotNull(encryptionResult.encrypted);
        Assert.NotEmpty(encryptionResult.encrypted);
    }

    [Fact]
    public void Decrypt_ValidKeyAndAutoNonce_ReturnsSuccessStateAndEncryptedBytes()
    {
        // Arrange
        string plaintextString = "Hello, World!";
        byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintextString);
        byte[] key = Aes256Gcm.GenerateKey();

        // Act
        (bool success, byte[] encrypted) encryptionResult = Aes256Gcm.Encrypt(key, plaintextBytes);
        (bool success, byte[] plaintext) decryptionResult = Aes256Gcm.Decrypt(
            key,
            encryptionResult.encrypted
        );

        // Assert
    }

    [Fact]
    public void GenerateKey_ReturnsCorrectSize()
    {
        byte[] key = Aes256Gcm.GenerateKey();
        Assert.NotNull(key);
        Assert.Equal(Aes256Gcm.KeySizeBytes, key.Length);
    }

    [Fact]
    public void _()
    {
        byte[] key = Aes256Gcm.GenerateKey();
        Assert.NotNull(key);
        Assert.Equal(Aes256Gcm.KeySizeBytes, key.Length);
    }
}
