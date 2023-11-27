using System.Numerics;
using EncryptionCore;

namespace UnitTests;

[TestFixture]
public class RsaOAEPEncryptionTests
{
    [Test]
    public void TestEncryptionAndDecryption()
    {
        // Arrange
        var originalData = "Hello, OAEP!"u8.ToArray();
        
        var rsa = new Rsa(2048);
        
        // Act
        var encrypted = rsa.EncryptWithOAEP(new BigInteger(originalData));
        var decrypted = rsa.DecryptWithOAEP(encrypted);
        
        // Assert
        CollectionAssert.AreEqual(originalData, decrypted.ToByteArray());
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
        var encryptedData1 = rsa.EncryptWithOAEP(new BigInteger(data1));
        var encryptedData2 = rsa.EncryptWithOAEP(new BigInteger(data2));
        
        var decryptedData1 = rsa.DecryptWithOAEP(encryptedData1);
        var decryptedData2 = rsa.DecryptWithOAEP(encryptedData2);
        
        // Assert
        CollectionAssert.AreEqual(data1, decryptedData1.ToByteArray());
        CollectionAssert.AreEqual(data2, decryptedData2.ToByteArray());
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
        var encryptedData = rsa.EncryptWithOAEP(new BigInteger(emptyData));
        var decryptedData = rsa.DecryptWithOAEP(encryptedData);
        
        // Assert
        CollectionAssert.AreEqual(emptyData, decryptedData.ToByteArray());
    }
}