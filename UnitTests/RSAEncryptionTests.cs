using System.Numerics;
using EncryptionCore;

namespace UnitTests;

[TestFixture]
public class RsaEncryptionTests
{
    [Test]
    public void TestEncryptionAndDecryption()
    {
        // Arrange
        var originalData = "Hello, OAEP!"u8.ToArray();
        
        var rsa = new Rsa(2048);
        // var publicKey = rsa.PrintPublicKey();
        // var privateKey = rsa.PrintPrivateKey();
        
        // Act
        var encryptedData = rsa.Encrypt(new BigInteger(originalData));
        var decryptedData = rsa.Decrypt(encryptedData).ToByteArray();
        
        // Assert
        CollectionAssert.AreEqual(originalData, decryptedData);
    }

    [Test]
    public void TestDifferentInputs()
    {
        // Arrange
        var data1 = "Test Data 1"u8.ToArray();
        var data2 = "Test Data 2"u8.ToArray();
        
        var rsa = new Rsa(2048);
        // var publicKey = rsa.PrintPublicKey();
        // var privateKey = rsa.PrintPrivateKey();
        
        // Act
        var encryptedData1 = rsa.Encrypt(new BigInteger(data1));
        var encryptedData2 = rsa.Encrypt(new BigInteger(data2));
        
        var decryptedData1 = rsa.Decrypt(encryptedData1).ToByteArray();
        var decryptedData2 = rsa.Decrypt(encryptedData2).ToByteArray();
        
        // Assert
        CollectionAssert.AreEqual(data1, decryptedData1);
        CollectionAssert.AreEqual(data2, decryptedData2);
    }

    [Test]
    public void TestEmptyInput()
    {
        //Arrange 
        var emptyData = Array.Empty<byte>();
        
        var rsa = new Rsa(2048);
        // var publicKey = rsa.PrintPublicKey();
        // var privateKey = rsa.PrintPrivateKey();
        
        // Act
        var encryptedData = rsa.Encrypt(new BigInteger(emptyData));
        var decryptedData = rsa.Decrypt(encryptedData).ToByteArray();
        
        // Assert
        CollectionAssert.AreEqual(emptyData, decryptedData);
    }
}