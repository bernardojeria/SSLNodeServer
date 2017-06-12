using System;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SslClient
{
    class App
    {

        private static readonly string ServerHostName = "127.0.0.1";
        private static readonly int ServerPort = 3000;
       
        //private static readonly string ClientCertificateName = "MyClient";
        private static readonly string ClientCertificateFile = @"C:\Users\Ben\Desktop\xbrute_api\www\certs\certs\clientcert.p12";
        private static readonly string ClientCertificatePassword = "certpass";



        static void Main(string[] args)
        {
            //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11; ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            try
            {
                ////read from the store (must have a key there)
                //var store = new X509Store(StoreLocation.CurrentUser);
                //store.Open(OpenFlags.ReadOnly);
                //var clientCertificateCollection = store.Certificates.Find(X509FindType.FindBySubjectName, ClientCertificateName, false);

                //read from the file
                var clientCertificate = new X509Certificate2(ClientCertificateFile, ClientCertificatePassword);
                var clientCertificateCollection = new X509CertificateCollection(new X509Certificate[] { clientCertificate });

                TcpClient client = new TcpClient();
                client.Connect(ServerHostName, ServerPort);
                using (SslStream sslStream = new SslStream(client.GetStream(), false, App_CertificateValidation, SelectLocalCertificate))
                {
                    Console.WriteLine("Client connected.");

                    sslStream.AuthenticateAsClient(ServerHostName, clientCertificateCollection, SslProtocols.Tls12, true);//setting this to false works. altho i think i can ssl with any cert. trying callback
                    Console.WriteLine("SSL authentication completed.");
                    Console.WriteLine("SSL using local certificate {0}.", sslStream.LocalCertificate.Subject);
                    Console.WriteLine("SSL using remote certificate {0}.", sslStream.RemoteCertificate.Subject);

                    var outputMessage = "Hello from the client " + Process.GetCurrentProcess().Id.ToString() + ".";
                    var outputBuffer = Encoding.UTF8.GetBytes(outputMessage);
                    sslStream.Write(outputBuffer);
                    Console.WriteLine("Sent: {0}", outputMessage);

                    var inputBuffer = new byte[4096];
                    var inputBytes = 0;
                    while (inputBytes == 0)
                    {
                        inputBytes = sslStream.Read(inputBuffer, 0, inputBuffer.Length);
                    }
                    var inputMessage = Encoding.UTF8.GetString(inputBuffer, 0, inputBytes);
                    Console.WriteLine("Received: {0}", inputMessage);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("*** {0}\n*** {1}!", ex.GetType().Name, ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }
        //
        public static X509Certificate SelectLocalCertificate(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            Console.WriteLine("Client is selecting a local certificate.");
            if (acceptableIssuers != null &&
                acceptableIssuers.Length > 0 &&
                localCertificates != null &&
                localCertificates.Count > 0)
            {
                //string CA = @"C:\Users\Ben\Desktop\xbrute_api\www\certs\certs\clientcert.p12";
                //X509Certificate2 certificate = new X509Certificate2(CA, "ceaecaefrb");
                //string issuer = certificate.Issuer;
                //if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                //    return certificate;
                //return certificate;
                //Use the first certificate that is from an acceptable issuer.
                foreach (X509Certificate certificate in localCertificates)
                {
                    string issuer = certificate.Issuer;
                    if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                        return certificate;
                }
            }
            if (localCertificates != null &&
                localCertificates.Count > 0)
                return localCertificates[0];

            return null;
        }
        private static bool App_CertificateValidation(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // If the certificate is a valid, signed certificate, return true.
            if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
            {
                return true;
            }

            // If there are errors in the certificate chain, look at each error to determine the cause.
            if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                if (chain != null && chain.ChainStatus != null)
                {
                    foreach (System.Security.Cryptography.X509Certificates.X509ChainStatus status in chain.ChainStatus)
                    {
                        if ((certificate.Subject == certificate.Issuer) &&
                           (status.Status == System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.UntrustedRoot))
                        {
                            // Self-signed certificates with an untrusted root are valid. 
                            continue;
                        }
                        else
                        {
                            if (status.Status != System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.NoError)
                            {
                                // If there are any other errors in the certificate chain, the certificate is invalid,
                                // so the method returns false.
                                return false;
                            }
                        }
                    }
                }

                // When processing reaches this line, the only errors in the certificate chain are 
                // untrusted root errors for self-signed certificates. These certificates are valid
                // for default Exchange server installations, so return true.
                return true;
            }
            else
            {
                // In all other cases, return false.
                return false;
            }
        }
    }
}
