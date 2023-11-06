using System.Numerics;
using RsaImplementation;

var rsa = new Rsa(2048);
var publicKey = rsa.PrintPublicKey();
var privateKey = rsa.PrintPrivateKey();

// Console.WriteLine(publicKey);
// Console.WriteLine(privateKey);
//
// var rsa2 = new Rsa(publicKey, privateKey);
//
// Console.WriteLine("TEST MESSAGE 123123");
// var dataToEncrypt = new BigInteger("TEST MESSAGE 123123"u8.ToArray());
//
// var encrypted = rsa2.Encrypt(dataToEncrypt);
// Console.WriteLine("ENCRYPTED");
// encrypted.PrintToUtf8();
//
// var decrypted = rsa2.Decrypt(encrypted);
// Console.WriteLine("DECRYPTED");
// decrypted.PrintToUtf8();


Console.WriteLine("TEST MESSAGE 123123");
var padded = OAEP.Encode("TEST MESSAGE 123123".ToByteArray());
Console.WriteLine("Padded: ");
padded.PrintToBase64();
var paddedEncrypted = rsa.Encrypt(new BigInteger(padded));

Console.WriteLine("Padded Encrypted: ");
paddedEncrypted.PrintToUtf8();

var paddedDecrypted = rsa.Decrypt(paddedEncrypted);
Console.WriteLine("Padded Decrypted: ");
paddedDecrypted.PrintToBase64();

var unpadded = OAEP.Decode(paddedDecrypted.ToByteArray());
Console.WriteLine("Unpadded: ");
unpadded.PrintToUtf8();
