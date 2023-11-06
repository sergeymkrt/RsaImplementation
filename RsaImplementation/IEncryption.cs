using System.Numerics;

namespace RsaImplementation;

public interface IEncryption
{
    public string PrintPublicKey();
    public string PrintPrivateKey();
    public BigInteger Encrypt(BigInteger data);
    public BigInteger Decrypt(BigInteger data);
}