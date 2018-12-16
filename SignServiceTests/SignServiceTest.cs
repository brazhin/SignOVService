using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SignService;
using System.Security.Cryptography.X509Certificates;

namespace SignServiceTests
{
	[TestFixture]
	public class SignServiceTest
	{
		private const string gost2001 = "8067b09d8564842d4285e400cf91c27c72cf4d0f";
		private const string gost2012_256 = "af976d0aca919d3df62649501e92145b5ed59967";
		private const string gost2012_512 = "cbb3d9dca57072feb27ededfea37ce4d3bbffe3f"; // не используется
		private const string rsa = "0b386108cd0bc2ff596bb365803b069901a7f5db"; //не используется

		[Test]
		public void SignDataAllGostsTest()
		{
			SignServiceProvider provider = new SignServiceProvider(new LoggerFactory());
			var data = Utils.GetStreamFromFile("Assets\\Smev3\\SignDataTest.txt");

			string[] gostCertsThumbprint = new string[] { gost2001, gost2012_256, gost2012_512, rsa };

			for (int i = 0; i < gostCertsThumbprint.Length; i++)
			{
				var sign = provider.Sign(data, gostCertsThumbprint[i]);

				Assert.IsNotNull(sign);
				Assert.IsTrue(sign.Length > 0);

				X509Certificate2 cert = null;

				bool isVerify = provider.VerifyDetachedMessage(sign, data, false, ref cert);

				Assert.IsTrue(isVerify);
				Assert.IsNotNull(cert);
			}
		}

		[Test]
		public void SignXmlMr300GOST2001()
		{
			ExecuteOnDataList("Smev3\\DataWithoutSignature", Mr.MR300, gost2001);
		}

		[Test]
		public void SignXmlMr300GOST2012()
		{
			ExecuteOnDataList("Smev3\\DataWithoutSignature", Mr.MR300, gost2012_256);
		}

		[Test]
		public void SignXmlMr300GOST2001ReplaceSign()
		{
			ExecuteOnDataList("Smev3\\DataWithSignature", Mr.MR300, gost2001);
		}

		[Test]
		public void SignXmlMr300GOST2012ReplaceSign()
		{
			ExecuteOnDataList("Smev3\\DataWithSignature", Mr.MR300, gost2012_256);
		}

		[Test]
		public void SignXmlMr244GOST2001()
		{
			ExecuteOnDataList("Smev2\\Mr244", Mr.MR244, gost2001);
		}

		[Test]
		public void SignXmlMr244GOST2012()
		{
			ExecuteOnDataList("Smev2\\Mr244", Mr.MR244, gost2012_256);
		}

		[Test]
		public void SignXmlMr255GOST2001()
		{
			ExecuteOnDataList("Smev2\\Mr255", Mr.MR255, gost2001);
		}

		[Test]
		public void SignXmlMr255GOST2012()
		{
			ExecuteOnDataList("Smev2\\Mr255", Mr.MR255, gost2012_256);
		}

		private void ExecuteOnDataList(string directory, Mr mr, string thumbprint)
		{
			SignServiceProvider provider = new SignServiceProvider(new LoggerFactory());
			var files = Utils.GetFilesList(directory);

			foreach (var file in files)
			{
				var data = Utils.GetTextFromFile(file);
				var signedXml = provider.SignXml(data, mr, thumbprint);
			}
		}
	}
}
