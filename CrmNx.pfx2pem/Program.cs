using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CertificateManager;
using CommandLine;

namespace CrmNx.Pfx2Pem
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                var versionString = Assembly.GetEntryAssembly()
                    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                    .InformationalVersion
                    .ToString();
            
                Console.WriteLine($"dotnet-pfx2pem v{versionString}");
                Console.WriteLine("-------------");
                Console.WriteLine("\nUsage: dotnet pfx2pem [cert-needs-to-convert.pfx] [options]");
                Console.WriteLine("\nOptions:");
                Console.WriteLine("-h|--help        Display help screen.");
                Console.WriteLine("-p|--password    Password for certificate.");
                Console.WriteLine("-o|--outdir      Directory to write converted certificates.");
                return -1;
            }
            
            return await Parser.Default.ParseArguments<CommandLineOptions>(args)
                .MapResult(async (CommandLineOptions opts) =>
                    {
                        try
                        {
                            // We have the parsed arguments, so let's just pass them down
                            return await ConvertCertificate(opts.Path, opts.Password, opts.OutDirectory);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"{ex.Message}");
                            return -3; // Unhandled error
                        }
                    },
                    errs => Task.FromResult(-1)); // Invalid arguments
        }

        private static Task<int> ConvertCertificate(string path, string password, string outdir="")
        {
            string fullPath;

            if (Path.IsPathRooted(path))
            {
                fullPath = Path.GetFullPath(path);
            }
            else
            {
                var curDir = Directory.GetCurrentDirectory();
                fullPath = Path.GetFullPath(Path.Combine(curDir, path));
            }
            
            Console.WriteLine("Input---------------------------------");
            Console.WriteLine($"\t Certificate: {fullPath}");

            if (!File.Exists(fullPath))
            {
                Console.Error.WriteLine("Certificate file not found.");
                return Task.FromResult(-1);
            }

            var certName = Path.GetFileNameWithoutExtension(path);
            var dir = String.IsNullOrEmpty(outdir) ? Path.GetDirectoryName(fullPath) : outdir;

            if (!Directory.Exists(dir))
            {
                Console.Error.WriteLine($"Output directory not exist: {dir}");
                return Task.FromResult(-1);
            }
            
            Console.WriteLine($"\t Name: {certName}");
           
            var iec = new ImportExportCertificate();

            X509Certificate2 pfxCert;
            try
            {
                pfxCert = new X509Certificate2(fullPath, password,  X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Import pfx cert has been failed:");
                Console.Error.WriteLine(ex.Message);
                return Task.FromResult(-1);
            }
            
            Console.WriteLine("Output--------------------------------");

            // public key certificate as pem
            var publicPemFullPath = $"{dir}{Path.DirectorySeparatorChar}{certName}.pem";

            var exportPublicKeyCertificatePem = iec.PemExportPublicKeyCertificate(pfxCert);
            File.WriteAllText(publicPemFullPath, exportPublicKeyCertificatePem);
            
            Console.WriteLine($"\t Public key: {publicPemFullPath}");

            // private key
            string exportRsaPrivateKeyPem = string.Empty;
            var rsaPrivateKeyFullPath = $"{dir}{Path.DirectorySeparatorChar}{certName}.key";
            
            if (pfxCert.HasPrivateKey)
            {

                var loadedRsa = pfxCert.GetRSAPrivateKey();
                var exported = loadedRsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 1));

                RSA temp = RSA.Create();
                temp.ImportEncryptedPkcs8PrivateKey(password, exported, out _);
                
                var rsaPrivateKey = temp.ExportRSAPrivateKey();
                
                StringBuilder builder = new StringBuilder();
                builder.AppendLine(PemDecoder.GetBegin(PemTypes.RSA_PRIVATE_KEY));
                builder.AppendLine(Convert.ToBase64String(rsaPrivateKey,
                    Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine(PemDecoder.GetEnd(PemTypes.RSA_PRIVATE_KEY));
                // return builder.ToString();

                exportRsaPrivateKeyPem = builder.ToString();
            }
            else
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine(PemDecoder.GetBegin(PemTypes.RSA_PRIVATE_KEY));
                builder.AppendLine(PemDecoder.GetEnd(PemTypes.RSA_PRIVATE_KEY));
                
                exportRsaPrivateKeyPem = builder.ToString();
            }
            File.WriteAllText(rsaPrivateKeyFullPath, exportRsaPrivateKeyPem);

            Console.WriteLine($"\t Private RSA key: {rsaPrivateKeyFullPath}");

            

            return  Task.FromResult(0);
        }
    }
}