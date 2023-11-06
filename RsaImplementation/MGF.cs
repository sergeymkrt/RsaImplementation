using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace RsaImplementation;

/// <summary>
/// MGF1 implementation
/// </summary>
public static class MGF1
{
    public static byte[] Generate(byte[] seed, int maskLen)
    {
        IDigest digest = new Sha256Digest();

        var mgf1 = new Mgf1BytesGenerator(digest);
        mgf1.Init(new MgfParameters(seed));

        var output = new byte[maskLen];
        mgf1.GenerateBytes(output, 0, maskLen);

        return output;
    }
}
