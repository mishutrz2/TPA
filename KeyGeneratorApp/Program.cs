using System.Security.Cryptography;
using System.Text;

string keyDirectoryPath = Path.Combine(Environment.CurrentDirectory, "Keys");

if (!Directory.Exists(keyDirectoryPath))
{
    Directory.CreateDirectory(keyDirectoryPath);
}

var rsa = RSA.Create();
string privateKeyXml = rsa.ToXmlString(true);
string publicKeyXml = rsa.ToXmlString(false);

using var privateFile = File.Create(Path.Combine(keyDirectoryPath, "PrivateKey.xml"));
using var publicFile = File.Create(Path.Combine(keyDirectoryPath, "PublicKey.xml"));

privateFile.Write(Encoding.UTF8.GetBytes(privateKeyXml));
publicFile.Write(Encoding.UTF8.GetBytes(publicKeyXml));