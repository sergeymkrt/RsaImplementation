using System.Numerics;
using BenchmarkDotNet.Attributes;
using EncryptionCore;

namespace RsaImplementation;

public class Benchmarks
{
    private const int KeySize = 2048;
    // private const int MessageSize = 256;
    // private const int Iterations = 100;

    // private readonly byte[] _message = new byte[MessageSize];
    
    private readonly string _message = "Hello World";
    private string buffer = string.Empty;
    
    private readonly Rsa rsa = new(KeySize);
    
    [Benchmark]
    public void Encrypt()
    {
        var messageBigInt = new BigInteger(_message.ToByteArray());
        rsa.Encrypt(messageBigInt);
        buffer = messageBigInt.ToString();
    }

    [Benchmark]
    public void Decrypt()
    {
        var messageBigInt = new BigInteger(buffer.ToByteArray());
        rsa.Decrypt(messageBigInt);
    }

    [Benchmark]
    public void EncryptWithOAEP()
    {
        
    }
}