using CommandLine;

namespace CrmNx.Pfx2Pem
{
    public class CommandLineOptions
    {
        [Value(index: 0, Required = true, HelpText = "Certificate file Path to convert.")]
        public string Path { get; set; }
        
        [Option(shortName: 'p', longName: "password", Required = false, HelpText = "Password for certificate.", Default = "")]
        public string Password { get; set; }
        
        [Option(shortName: 'o', longName: "outdir", Required = false, HelpText = "Directory to write converted certificates.", Default = "")]
        public string OutDirectory { get; set; }
    }
}