using System;
using System.Security.Cryptography;
using FCLX509 = System.Security.Cryptography.X509Certificates;
using WSEX509 = Microsoft.Web.Services2.Security.X509;

namespace X509Application
{
	class X509Class
	{
		[STAThread]
		static void Main(string[] args)
		{
			GetKeys();
			WSEStore();
			FCLx509();
			WSEx509();
		}
		static void GetKeys()
		{
			string subjectname = "CN=Administrator";

			//Don't use X509CertificateStore.MyStore. It incorrectly defines the personal certficate store as "My" and not "MY"
			string storename ="MY";

			//Local Machine HKEY_LOCAL_MACHINE\Software\Microsoft\SystemCertificates
			WSEX509.X509CertificateStore.StoreLocation location = WSEX509.X509CertificateStore.StoreLocation.LocalMachine;

			//We are opening the System Store
			WSEX509.X509CertificateStore.StoreProvider provider = WSEX509.X509CertificateStore.StoreProvider.System;
			
			//Construct the store
			WSEX509.X509CertificateStore store = new WSEX509.X509CertificateStore(provider, location, storename);

			//Open for read only.
			bool fopen = store.OpenRead();

			//Display the number of certificates in the store
			System.Console.Out.WriteLine("Store Location : " + store.Location);
			System.Console.Out.WriteLine("Store Name     : " + storename);
			System.Console.Out.WriteLine("Store Provider : " + provider);
			System.Console.Out.WriteLine("Total Certficates    : " + store.Certificates.Count);

			//Search for the certificate in the store based on the subject name (exact match)
			WSEX509.X509CertificateCollection cers = store.FindCertificateBySubjectName(subjectname);
			System.Console.Out.WriteLine("Certficates with '{0}' subjectname :  {1}",subjectname,cers.Count);

			foreach ( FCLX509.X509Certificate FCLcer in cers) 
			{
				//Construst the WSE 1.0 X509Certificate class
				WSEX509.X509Certificate cer = new WSEX509.X509Certificate(FCLcer.GetRawCertData());

				//Dump the Version 1 Fields of X509 Certificates
				System.Console.Out.WriteLine("Serial Number : " + cer.GetSerialNumberString());

				//Extract the public key from the certificate.
				AsymmetricAlgorithm public_key = cer.PublicKey;
				System.Console.Out.WriteLine("Public Key : " + public_key.ToXmlString(false));

				//Extract the private key from the certificate.
				AsymmetricAlgorithm private_key = cer.Key;
				System.Console.Out.WriteLine("Private Key : " + private_key.ToXmlString(true));
			}
		}

		static void FCLx509()
		{
			FCLX509.X509Certificate cer = FCLX509.X509Certificate.CreateFromCertFile(@"c:\test.cer");
			System.Console.Out.WriteLine("Serial Number : " + cer.GetSerialNumberString());
			System.Console.Out.WriteLine("Effective Date : " + cer.GetEffectiveDateString());
			System.Console.Out.WriteLine("Expiration Date : " + cer.GetExpirationDateString());
			System.Console.Out.WriteLine("Entity Name : " + cer.GetName());
			System.Console.Out.WriteLine("Entities Public Key : " + cer.GetPublicKeyString());
			System.Console.Out.WriteLine("Entities Public Key Algorithm : : " + cer.GetKeyAlgorithm());
			System.Console.Out.WriteLine("Issuers Name: " + cer.GetIssuerName());
		}

		static void WSEx509()
		{
			//Load the certificate from the DER Encoded Certficate file.
			FCLX509.X509Certificate FCLcer = WSEX509.X509Certificate.CreateFromCertFile(@"c:\w2k-as-1224.PGVIJAY.com_Pgvijay.cer");

			//Construst the WSE 1.0 X509Certificate class
			WSEX509.X509Certificate cer = new WSEX509.X509Certificate(FCLcer.GetRawCertData());

			//Dump the Version 1 Fields of X509 Certificates
			System.Console.Out.WriteLine("Serial Number : " + cer.GetSerialNumberString());
			System.Console.Out.WriteLine("Effective Date : " + cer.GetEffectiveDateString());
			System.Console.Out.WriteLine("Expiration Date : " + cer.GetExpirationDateString());
			System.Console.Out.WriteLine("Entity Name : " + cer.GetName());
			System.Console.Out.WriteLine("Entities Public Key : " + cer.GetPublicKeyString());
			System.Console.Out.WriteLine("Entities Public Key Algorithm : " + cer.GetKeyAlgorithm());
			System.Console.Out.WriteLine("Issuers Name: " + cer.GetIssuerName());
			
			//Dump the Version 3 Key usage extenstions of X509 Certificates
			System.Console.Out.WriteLine("SupportsDataEncryption : " + cer.SupportsDataEncryption);
			System.Console.Out.WriteLine("SupportsDigitalSignature : " + cer.SupportsDigitalSignature);

			//Extract the private key from the certificate.
			AsymmetricAlgorithm private_key = cer.Key;
			System.Console.Out.WriteLine("Private Key : " + private_key.ToXmlString(true));

		}
	

		static void WSEStore()
		{
			//Don't use X509CertificateStore.MyStore. It incorrectly defines the personal certficate store as "My" and not "MY"
			string storename ="MY";// @"C:\Program Files\Microsoft Visual Studio\MyProjects\test\TestStor.sto";//"MY";


			//Local Machine HKEY_LOCAL_MACHINE\Software\Microsoft\SystemCertificates
			WSEX509.X509CertificateStore.StoreLocation location = WSEX509.X509CertificateStore.StoreLocation.LocalMachine;

			//We are opening the System Store
			WSEX509.X509CertificateStore.StoreProvider provider = WSEX509.X509CertificateStore.StoreProvider.System;
			
			//Construct the store
			WSEX509.X509CertificateStore store = new WSEX509.X509CertificateStore(provider,location, storename);

			//Open for read only.
			bool fopen = store.OpenRead();

			//Display the number of certificates in the store
			System.Console.Out.WriteLine("Store Location : " + location);
			System.Console.Out.WriteLine("Store Name     : " + storename);
			System.Console.Out.WriteLine("Store Provider : " + provider);
			System.Console.Out.WriteLine("Certficates    : " + store.Certificates.Count);

			//Search for the certificate in the store based on the subject name (exact match)
			WSEX509.X509CertificateCollection cers = store.FindCertificateBySubjectName("CN=Administrator");
			System.Console.Out.WriteLine("Certficates    : " + cers.Count);


			//Search for the certificate in the store based on the subject name (substring match)
			cers = store.FindCertificateBySubjectString("Administrator");
			System.Console.Out.WriteLine("Certficates    : " + cers.Count);

			foreach ( FCLX509.X509Certificate FCLcer in store.Certificates) 
			{
				//Construst the WSE 1.0 X509Certificate class
				WSEX509.X509Certificate cer = new WSEX509.X509Certificate(FCLcer.GetRawCertData());

				//Dump the Version 1 Fields of X509 Certificates
				System.Console.Out.WriteLine("Serial Number : " + cer.GetSerialNumberString());
				System.Console.Out.WriteLine("Effective Date : " + cer.GetEffectiveDateString());
				System.Console.Out.WriteLine("Expiration Date : " + cer.GetExpirationDateString());
				System.Console.Out.WriteLine("Entity Name : " + cer.GetName());
				System.Console.Out.WriteLine("Entities Public Key : " + cer.GetPublicKeyString());
				System.Console.Out.WriteLine("Entities Public Key Algorithm : " + cer.GetKeyAlgorithm());
				System.Console.Out.WriteLine("Issuers Name: " + cer.GetIssuerName());
			
				//Dump the Version 3 Key usage extenstions of X509 Certificates
				System.Console.Out.WriteLine("SupportsDataEncryption : " + cer.SupportsDataEncryption);
				System.Console.Out.WriteLine("SupportsDigitalSignature : " + cer.SupportsDigitalSignature);

				//Extract the private key from the certificate.
				try	
				{
					AsymmetricAlgorithm private_key = cer.Key ;
					System.Console.Out.WriteLine("Private Key : " + private_key.ToXmlString(true));
				}
				catch(Exception es)
				{
					System.Console.Out.WriteLine("Private Key : Non-Exportable" );
				}
			}

		}
	}
}
