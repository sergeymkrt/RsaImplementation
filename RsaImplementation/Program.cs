using System.Numerics;
using System.Text;
using RsaImplementation;

var rsa = new Rsa(2048);
var publicKey = rsa.PrintPublicKey();
var privateKey = rsa.PrintPrivateKey();

Console.WriteLine(publicKey);
Console.WriteLine(privateKey);

Console.WriteLine("TEST MESSAGE 123123");
var dataToEncrypt = new BigInteger("TEST MESSAGE 123123"u8.ToArray());

var encrypted = rsa.Encrypt(dataToEncrypt);
var encryptedInBytes = encrypted.ToByteArray();
var encryptedInText = Encoding.UTF8.GetString(encryptedInBytes);
Console.WriteLine("ENCRYPTED");
Console.WriteLine(encryptedInText);

var decrypted = rsa.Decrypt(encrypted);
var decryptedInBytes = decrypted.ToByteArray();
var decryptedInText = Encoding.UTF8.GetString(decryptedInBytes);
Console.WriteLine("DECRYPTED");
Console.WriteLine(decryptedInText);