using System.Numerics;
using BenchmarkDotNet.Attributes;
using EncryptionCore;

namespace RsaImplementation;

public class Benchmarks
{
    private const int KeySize = 2048;
    private const int MessageSize = 256;
    private const int Iterations = 100;

    private readonly byte[] _message = new byte[MessageSize];
    
    private readonly Rsa rsa = new(KeySize);
    
    [Benchmark]
    public void Encrypt()
    {
        for (var i = 0; i < Iterations; i++)
        {
            rsa.Encrypt(new BigInteger(_message));
        }
    }

    [Benchmark]
    public void Decrypt()
    {
        for (var i = 0; i < Iterations; i++)
        {
            rsa.Decrypt(new BigInteger(_message));
        }
    }
}