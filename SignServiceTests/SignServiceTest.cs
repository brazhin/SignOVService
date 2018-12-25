using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SignService;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SignServiceTests
{
	[TestFixture]
	public class SignServiceTest
	{
		private const string Gost2001CryptoPro = "8067b09d8564842d4285e400cf91c27c72cf4d0f";
		private const string Gost2012_256CryptoPro = "af976d0aca919d3df62649501e92145b5ed59967";
		private const string Gost2012_512CryptoPro = "cbb3d9dca57072feb27ededfea37ce4d3bbffe3f";

		private const string Gost2001VipNet = "";
		private const string Gost2012_256VipNet = "58282f9009e385aa4ff45a611bf7f5666f9352ef";
		private const string Gost2012_512VipNet = "";

		private const string Mr300 = "Smev3";
		private const string Mr244 = "Smev2\\Mr244";
		private const string Mr255 = "Smev2\\Mr255";

		private const string TestHashData = "TestHashData";
		private const string TestSignData = "TestSignData";


		// VipNet tests

		[Test]
		public void CreateHashGost2001VipNetTest()
		{
			CreateHashExecuteTest(CspType.VipNet, TestHashData, Gost2001VipNet);
		}

		[Test]
		public void CreateHashGost2012_256VipNetTest()
		{
			CreateHashExecuteTest(CspType.VipNet, TestHashData, Gost2012_256VipNet);
		}

		[Test]
		public void CreateHashGost2012_512VipNetTest()
		{
			CreateHashExecuteTest(CspType.VipNet, TestHashData, Gost2012_512VipNet);
		}

		[Test]
		public void SignDataGost2001VipNetTest()
		{
			SignDataExecuteTest(CspType.VipNet, TestSignData, Gost2001VipNet);
		}

		[Test]
		public void SignDataGost2012_256VipNetTest()
		{
			SignDataExecuteTest(CspType.VipNet, TestSignData, Gost2012_256VipNet);
		}

		[Test]
		public void SignDataGost2012_512VipNetTest()
		{
			SignDataExecuteTest(CspType.VipNet, TestSignData, Gost2012_512VipNet);
		}

		[Test]
		public void SignSoapSmev3Gost2001VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr300, Mr.MR300, Gost2001VipNet);
		}

		[Test]
		public void SignSoapSmev3Gost2012_256VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr300, Mr.MR300, Gost2012_256VipNet);
		}

		[Test]
		public void SignSoapSmev3Gost2012_512VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr300, Mr.MR300, Gost2012_512VipNet);
		}

		[Test]
		public void SignSoapSmev244Gost2001VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr244, Mr.MR244, Gost2001VipNet);
		}

		[Test]
		public void SignSoapSmev244Gost2012_256VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr244, Mr.MR244, Gost2012_256VipNet);
		}

		[Test]
		public void SignSoapSmev244Gost2012_512VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr244, Mr.MR244, Gost2012_512VipNet);
		}

		[Test]
		public void SignSoapSmev255Gost2001VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr255, Mr.MR255, Gost2001VipNet);
		}

		[Test]
		public void SignSoapSmev255Gost2012_256VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr255, Mr.MR255, Gost2012_256VipNet);
		}

		[Test]
		public void SignSoapSmev255Gost2012_512VipNetTest()
		{
			SignSoapExecuteTest(CspType.VipNet, Mr255, Mr.MR255, Gost2012_512VipNet);
		}

		// CryptoPro tests

		[Test]
		public void CreateHashGost2001CryptoProTest()
		{
			CreateHashExecuteTest(CspType.CryptoPro, TestHashData, Gost2001CryptoPro);
		}

		[Test]
		public void CreateHashGost2012_256CryptoProTest()
		{
			CreateHashExecuteTest(CspType.CryptoPro, TestHashData, Gost2012_256CryptoPro);
		}

		[Test]
		public void CreateHashGost2012_512CryptoProTest()
		{
			CreateHashExecuteTest(CspType.CryptoPro, TestHashData, Gost2012_512CryptoPro);
		}

		[Test]
		public void SignDataGost2001CryptoProTest()
		{
			SignDataExecuteTest(CspType.CryptoPro, TestSignData, Gost2001CryptoPro);
		}

		[Test]
		public void SignDataGost2012_256CryptoProTest()
		{
			SignDataExecuteTest(CspType.CryptoPro, TestSignData, Gost2012_256CryptoPro);
		}

		[Test]
		public void SignDataGost2012_512CryptoProTest()
		{
			SignDataExecuteTest(CspType.CryptoPro, TestSignData, Gost2012_512CryptoPro);
		}

		[Test]
		public void SignSoapSmev3Gost2001CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr300, Mr.MR300, Gost2001CryptoPro);
		}

		[Test]
		public void SignSoapSmev3Gost2012_256CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr300, Mr.MR300, Gost2012_256CryptoPro);
		}

		[Test]
		public void SignSoapSmev3Gost2012_512CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr300, Mr.MR300, Gost2012_512CryptoPro);
		}

		[Test]
		public void SignSoapSmev244Gost2001CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr244, Mr.MR244, Gost2001CryptoPro);
		}

		[Test]
		public void SignSoapSmev244Gost2012_256CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr244, Mr.MR244, Gost2012_256CryptoPro);
		}

		[Test]
		public void SignSoapSmev244Gost2012_512CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr244, Mr.MR244, Gost2012_512CryptoPro);
		}

		[Test]
		public void SignSoapSmev255Gost2001CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr255, Mr.MR255, Gost2001CryptoPro);
		}

		[Test]
		public void SignSoapSmev255Gost2012_256CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr255, Mr.MR255, Gost2012_256CryptoPro);
		}

		[Test]
		public void SignSoapSmev255Gost2012_512CryptoProTest()
		{
			SignSoapExecuteTest(CspType.CryptoPro, Mr255, Mr.MR255, Gost2012_512CryptoPro);
		}

		/// <summary>
		/// Метод выполнения тестов формирования хэш
		/// </summary>
		/// <param name="csp"></param>
		/// <param name="directory"></param>
		/// <param name="thumbprint"></param>
		private void CreateHashExecuteTest(CspType csp, string directory, string thumbprint)
		{
			SignServiceProvider provider = new SignServiceProvider(csp, new LoggerFactory());
			var files = Utils.GetFilesList(directory);

			foreach (var file in files)
			{
				var data = Utils.GetStreamFromFile(file);
				var stream = new MemoryStream(data);
				var hash = provider.CreateHash(stream, thumbprint);

				Assert.IsTrue(!string.IsNullOrEmpty(hash));
			}
		}

		/// <summary>
		/// Метод выполнения тестов подписи данных
		/// </summary>
		/// <param name="csp"></param>
		/// <param name="directory"></param>
		/// <param name="thumbprint"></param>
		private void SignDataExecuteTest(CspType csp, string directory, string thumbprint)
		{
			SignServiceProvider provider = new SignServiceProvider(csp, new LoggerFactory());
			var files = Utils.GetFilesList(directory);

			foreach (var file in files)
			{
				var data = Utils.GetStreamFromFile(file);
				var sign = provider.Sign(data, thumbprint);

				Assert.IsNotNull(sign);
				Assert.IsTrue(sign.Length > 0);

				X509Certificate2 cert = null;

				bool isVerify = provider.VerifyDetachedMessage(sign, data, false, ref cert);

				Assert.IsTrue(isVerify);
				Assert.IsNotNull(cert);
			}
		}

		/// <summary>
		/// Метод выполнения тестов подписи Soap сообщений СМЭВ
		/// </summary>
		/// <param name="csp"></param>
		/// <param name="directory"></param>
		/// <param name="mr"></param>
		/// <param name="thumbprint"></param>
		private void SignSoapExecuteTest(CspType csp, string directory, Mr mr, string thumbprint)
		{
			SignServiceProvider provider = new SignServiceProvider(csp, new LoggerFactory());
			var files = Utils.GetFilesList(directory);

			foreach (var file in files)
			{
				var data = Utils.GetTextFromFile(file);
				var signedXml = provider.SignSoap(data, mr, thumbprint);

				Assert.IsTrue(!string.IsNullOrEmpty(signedXml));
			}
		}
	}
}
