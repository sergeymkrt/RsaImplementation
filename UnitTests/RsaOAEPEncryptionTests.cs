using System.Security.Cryptography;
using System.Text;

namespace UnitTests;

[TestFixture]
public class RsaOAEPEncryptionTests
{
    // [Test]
    // public void TestEncryptionAndDecryption()
    // {
    //     // Arrange
    //     var originalData = "Hello, OAEP!"u8.ToArray();
    //
    //     var rsa = new Rsa(2048);
    //
    //     // Act
    //     // var paddedPlain = OAEP.Encode(originalData);
    //     // var reversedPaddedPlain = paddedPlain.Reverse().ToArray();
    //     // var encrypted = rsa.Encrypt(new BigInteger(reversedPaddedPlain));
    //     // var decrypted = rsa.Decrypt(encrypted);
    //     // var decryptedPadded = decrypted.ToByteArray().Reverse().ToArray();
    //     // var decryptedData = OAEP.Decode(decryptedPadded);
    //
    //     var encryptedData = rsa.EncryptWithOAEP(new BigInteger(originalData));
    //     var decryptedData = rsa.DecryptWithOAEP(encryptedData);
    //
    //     // Assert
    //     CollectionAssert.AreEqual(originalData, decryptedData);
    // }
    //
    // [Test]
    // public void TestDifferentInputs()
    // {
    //     // Arrange
    //     var data1 = "Test Data 1"u8.ToArray();
    //     var data2 = "Test Data 2"u8.ToArray();
    //
    //     var rsa = new Rsa(2048);
    //     // var publicKey = rsa.PrintPublicKey();
    //     // var privateKey = rsa.PrintPrivateKey();
    //
    //     // Act
    //     var encryptedData1 = rsa.EncryptWithOAEP(new BigInteger(data1));
    //     var encryptedData2 = rsa.EncryptWithOAEP(new BigInteger(data2));
    //
    //     var decryptedData1 = rsa.DecryptWithOAEP(encryptedData1);
    //     var decryptedData2 = rsa.DecryptWithOAEP(encryptedData2);
    //
    //     // Assert
    //     CollectionAssert.AreEqual(data1, decryptedData1);
    //     CollectionAssert.AreEqual(data2, decryptedData2);
    // }
    //
    // [Test]
    // public void TestEmptyInput()
    // {
    //     //Arrange 
    //     var emptyData = Array.Empty<byte>();
    //
    //     var rsa = new Rsa(2048);
    //     // var publicKey = rsa.PrintPublicKey();
    //     // var privateKey = rsa.PrintPrivateKey();
    //
    //     // Act
    //     var encryptedData = rsa.EncryptWithOAEP(new BigInteger(emptyData));
    //     var decryptedData = rsa.DecryptWithOAEP(encryptedData);
    //
    //     // Assert
    //     CollectionAssert.AreEqual(emptyData, decryptedData);
    // }


    [Test]
    public void EncryptAndDecrypt_Successful()
    {
        // Arrange
        using var rsa = RSA.Create();
        var originalDataString = "Hello World";
        var originalData = Encoding.UTF8.GetBytes(originalDataString);

        // Act
        var encryptedData = rsa.Encrypt(originalData, RSAEncryptionPadding.OaepSHA256);
        var decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);

        // Assert
        Assert.That(decryptedData, Is.EqualTo(originalData));
    }

    [Test]
    public void EncryptWithInvalidPublicKey_ThrowsException()
    {
        // Arrange
        var invalidPublicKey = new byte[] { 0x01, 0x02, 0x03 }; // Invalid public key length

        // Act & Assert
        Assert.Throws<CryptographicException>(() => EncryptWithOAEP(invalidPublicKey, new byte[16]));
    }

    [Test]
    public void DecryptWithInvalidPrivateKey_ThrowsException()
    {
        // Arrange
        var invalidPrivateKey = new byte[] { 0x01, 0x02, 0x03 }; // Invalid private key length

        // Act & Assert
        Assert.Throws<CryptographicException>(() => DecryptWithOAEP(invalidPrivateKey, new byte[16]));
    }

    [Test]
    public void DecryptWithIncorrectPrivateKey_ThrowsException()
    {
        // Arrange
        using var rsa1 = RSA.Create();
        using var rsa2 = RSA.Create();
        var publicKey1 = rsa1.ExportRSAPublicKey();
        var privateKey2 = rsa2.ExportRSAPrivateKey();

        var encryptedData = rsa1.Encrypt(new byte[16], RSAEncryptionPadding.OaepSHA256);

        // Act & Assert
        Assert.Throws<CryptographicException>(() => DecryptWithOAEP(privateKey2, encryptedData));
    }

    private byte[] EncryptWithOAEP(byte[] publicKey, byte[] dataToEncrypt)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);
        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
    }

    private byte[] DecryptWithOAEP(byte[] privateKey, byte[] encryptedData)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);
        return rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
    }
}