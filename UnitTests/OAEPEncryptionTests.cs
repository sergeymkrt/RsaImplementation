using System.Text;
using EncryptionCore;

namespace UnitTests;

[TestFixture]
public class OAEPEncryptionTests
{
    [Test]
    public void TestEncryptionAndDecryption()
    {
        // Arrange
        var originalData = "Hello, OAEP!"u8.ToArray();
        
        // Act
        var encryptedData = OAEP.Encode(originalData);
        var decryptedData = OAEP.Decode(encryptedData);
        
        // Assert
        CollectionAssert.AreEqual(originalData, decryptedData);
    }

    [Test]
    public void TestDifferentInputs()
    {
        // Arrange
        var data1 = "Test Data 1"u8.ToArray();
        var data2 = "Test Data 2"u8.ToArray();
        
        // Act
        var encryptedData1 = OAEP.Encode(data1);
        var encryptedData2 = OAEP.Encode(data2);
        
        var decryptedData1 = OAEP.Decode(encryptedData1);
        var decryptedData2 = OAEP.Decode(encryptedData2);
        
        // Assert
        CollectionAssert.AreEqual(data1, decryptedData1);
        CollectionAssert.AreEqual(data2, decryptedData2);
    }

    [Test]
    public void TestEmptyInput()
    {
        // Arrange
        var emptyData = Array.Empty<byte>();
        
        // Act
        var encryptedData = OAEP.Encode(emptyData);
        var decryptedData = OAEP.Decode(encryptedData);
        
        // Assert
        CollectionAssert.AreEqual(emptyData, decryptedData);
    }
}