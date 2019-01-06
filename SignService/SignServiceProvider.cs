using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Unix;
using SignService.Win;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using static SignService.CApiExtConst;

namespace SignService
{
	/// <summary>
	/// Класс для выполнения криптографических операций
	/// </summary>
	public class SignServiceProvider
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly ILogger<SignServiceProvider> log;

		public SignServiceProvider(CspType csp, ILoggerFactory loggerFactory)
		{
			// Задаем тип используемого Криптопровайдера
			Csp = csp;

			this.loggerFactory = loggerFactory;
			this.log = loggerFactory.CreateLogger<SignServiceProvider>();
		}

		/// <summary>
		/// Тип используемого криптопровайдера
		/// </summary>
		internal static CspType Csp { get; private set; }

		/// <summary>
		/// Метод подписи XML
		/// </summary>
		/// <param name="xml"></param>
		/// <param name="mr"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		public string SignSoap(string xml, Mr mr, string thumbprint, string password)
		{
			string signedXml = string.Empty;

			if (SignServiceUtils.IsUnix)
			{
				log.LogDebug($"Попытка выполнить метод подписания XML под Unix платформой.");
				var unixService = new SignServiceUnix(loggerFactory);
				signedXml = unixService.SignSoap(xml, mr, thumbprint, password);
			}
			else
			{
				log.LogDebug($"Попытка выполнить метод подписания XML под Windows платформой.");
				var winService = new SignServiceWin(loggerFactory);
				signedXml = winService.SignSoap(xml, mr, thumbprint, password);
			}

			return signedXml;
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="certificate"></param>
		/// <param name="pluginHashAlg"></param>
		/// <returns></returns>
		public string CreateHash(Stream data, IntPtr certificate, ref int pluginHashAlg)
		{
			log.LogDebug("Получаем значение алгоритма публичного ключа.");

			var certContext = Marshal.PtrToStructure<CERT_CONTEXT>(certificate);
			var certInfo = Marshal.PtrToStructure<CERT_INFO>(certContext.pCertInfo);

			string publicKeyAlg = certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId;

			return ComputeHash(data, publicKeyAlg, ref pluginHashAlg);
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="certificate"></param>
		/// <param name="pluginHashAlg"></param>
		/// <returns></returns>
		public string CreateHash(Stream data, IntPtr certificate)
		{
			int plugHashAlg = 0;
			return CreateHash(data, certificate, ref plugHashAlg);
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		public string CreateHash(Stream data, X509Certificate2 certificate, ref int pluginHashAlg)
		{
			log.LogDebug("Получаем значение алгоритма публичного ключа.");
			string publicKeyAlg = certificate.PublicKey.Oid.Value;

			return ComputeHash(data, publicKeyAlg, ref pluginHashAlg);
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		public string CreateHash(Stream data, X509Certificate2 certificate)
		{
			int hashAlg = 0;
			return CreateHash(data, certificate, ref hashAlg);
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		public string CreateHash(Stream data, string thumbprint)
		{
			var hCert = GetCertificateHandle(thumbprint);
			return CreateHash(data, hCert);
		}

		/// <summary>
		/// Метод получения списка доверительных сертификатов
		/// </summary>
		/// <returns></returns>
		public X509Certificate2Collection GetTrustedCertificates()
		{
			X509Certificate2Collection confCertificates = new X509Certificate2Collection();

			if (SignServiceUtils.IsUnix)
			{
				var unixService = new SignServiceUnix(loggerFactory);
				confCertificates = unixService.GetTrustedCertificates();
			}
			else
			{
				var winService = new SignServiceWin(loggerFactory);
				confCertificates = winService.GetTrustedCertificates();
			}

			return confCertificates;
		}

		/// <summary>
		/// Метод проверки открепленной подписи
		/// </summary>
		/// <param name="sign"></param>
		/// <returns></returns>
		public bool VerifyDetachedMessage(byte[] sign, byte[] data, bool isCheckTrusted, ref X509Certificate2 certFromSign)
		{
			if (SignServiceUtils.IsUnix)
			{
				log.LogDebug("Выполняем проверку открепленной подписи под Unix платформой.");
				var unixService = new SignServiceUnix(loggerFactory);
				return unixService.VerifyDetachedMessage(sign, data, isCheckTrusted, ref certFromSign);
			}
			else
			{
				log.LogDebug("Выполняем проверку открепленной подписи под Windows платформой.");
				var winService = new SignServiceWin(loggerFactory);
				return winService.VerifyDetachedMessage(sign, data, isCheckTrusted, ref certFromSign);
			}
		}

		/// <summary>
		/// Метод подписи данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		public byte[] Sign(byte[] data, string thumbprint)
		{
			if (SignServiceUtils.IsUnix)
			{
				var unixService = new SignServiceUnix(loggerFactory);
				return unixService.Sign(data, thumbprint);
			}
			else
			{
				var winService = new SignServiceWin(loggerFactory);
				return winService.Sign(data, thumbprint);
			}
		}

		/// <summary>
		/// Метод получения хэндлера сертификата
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		public IntPtr GetCertificateHandle(string thumbprint)
		{
			if (SignServiceUtils.IsUnix)
			{
				var unixService = new SignServiceUnix(loggerFactory);
				return unixService.FindCertificate(thumbprint);
			}
			else
			{
				var winService = new SignServiceWin(loggerFactory);
				return winService.FindCertificate(thumbprint);
			}
		}

		/// <summary>
		/// Метод рассчета хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="publicKeyAlg"></param>
		/// <param name="pluginHashAlg"></param>
		/// <returns></returns>
		private string ComputeHash(Stream data, string publicKeyAlg, ref int pluginHashAlg)
		{
			log.LogDebug($"Определяем алгоритм хэширования по значению алгоритма публичного ключа: {publicKeyAlg}.");
			// Определение алгоритма.
			var algId = GetHashAlg(publicKeyAlg);

			log.LogDebug("Определяем идентификатор алгоритма для использования в плагине КриптоПро.");
			// Определение идентификатора алгоритма для использование в плагине КриптоПро.
			var hashAlgForPlugin = SignServiceUtils.GetHashCodeForPlugin(algId);
			pluginHashAlg = hashAlgForPlugin;

			log.LogDebug("Вычисляем хэш.");
			// Вычисление хэш.
			var base64Hash = GetHashBySigAlgId(data, algId);

			return base64Hash;
		}

		/// <summary>
		/// Метод получения алгоритма хэширования
		/// </summary>
		/// <param name="signatureAlgOid"></param>
		/// <returns></returns>
		private uint GetHashAlg(string publicKeyAlg)
		{
			string signatureAlgOid = SignServiceUtils.GetSignatureAlg(publicKeyAlg);

			if (SignServiceUtils.IsUnix)
			{
				log.LogDebug("Получаем алгоритм хэширования под Unix платформой.");

				var cryptOidInfo = SignServiceUnix.GetHashAlg(signatureAlgOid);
				return cryptOidInfo.Algid;
			}
			else
			{
				log.LogDebug("Получаем алгоритм хэширования под Windows платформой.");

				var cryptOidInfo = SignServiceWin.GetHashAlg(signatureAlgOid);
				return cryptOidInfo.Algid;
			}
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="algId"></param>
		/// <returns></returns>
		private string GetHashBySigAlgId(Stream data, uint algId)
		{
			if (SignServiceUtils.IsUnix)
			{
				log.LogDebug("Вычисляем хэш под Unix платформой.");
				var unixService = new SignServiceUnix(loggerFactory);
				return unixService.GetHashBySigAlgId(data, algId);
			}
			else
			{
				log.LogDebug("Вычисляем хэш под Windows платформой.");
				var winService = new SignServiceWin(loggerFactory);
				return winService.GetHashBySigAlgId(data, algId);
			}
		}
	}
}
