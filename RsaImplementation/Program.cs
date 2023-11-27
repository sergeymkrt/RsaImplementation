using System.Numerics;
using BenchmarkDotNet.Running;
using EncryptionCore;
using RsaImplementation;

// var summary = BenchmarkRunner.Run<Benchmarks>();

var rsa = new Rsa(2048);





var message = "Hello World";
var messageBigInt = new BigInteger(message.ToByteArray());
var encryptedMessage = rsa.EncryptWithOAEP(messageBigInt);

var decryptedMessage = rsa.DecryptWithOAEP(encryptedMessage);
var decryptedMessageString = decryptedMessage.ToByteArray().ToUtf8String();
Console.WriteLine($"Original message: {message}");




