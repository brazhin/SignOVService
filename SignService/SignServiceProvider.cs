using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Unix;
using SignService.Win;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SignService
{
	/// <summary>
	/// Класс для выполнения криптографических операций
	/// </summary>
	public class SignServiceProvider
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly ILogger<SignServiceProvider> log;

		public SignServiceProvider(ILoggerFactory loggerFactory)
		{
			this.loggerFactory = loggerFactory;
			this.log = loggerFactory.CreateLogger<SignServiceProvider>();
		}

		/// <summary>
		/// Свойство определяет тип платформы
		/// </summary>
		private bool IsUnix
		{
			get
			{
				int iPlatform = (int)Environment.OSVersion.Platform;
				return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
			}
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
		/// 
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
		/// Метод получения списка доверительных сертификатов
		/// </summary>
		/// <returns></returns>
		public X509Certificate2Collection GetTrustedCertificates()
		{
			X509Certificate2Collection confCertificates = new X509Certificate2Collection();

			if (IsUnix)
			{
				log.LogError("GetHashAlg failed. Отсутствует реализация для Unix системы.");
				throw new Exception("Отсутствует реализация для Unix системы.");
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
			if (IsUnix)
			{
				var unixService = new SignServiceUnix(loggerFactory);
				return unixService.VerifyDetachedMessage(sign, data, isCheckTrusted, ref certFromSign);
			}
			else
			{
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
			if (IsUnix)
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
		/// Метод получения алгоритма хэширования
		/// </summary>
		/// <param name="signatureAlgOid"></param>
		/// <returns></returns>
		private uint GetHashAlg(string publicKeyAlg)
		{
			string signatureAlgOid = SignServiceUtils.GetSignatureAlg(publicKeyAlg);

			if (IsUnix)
			{
				log.LogDebug("Получаем алгоритм хэширования под Windows платформой.");

				var unixService = new SignServiceUnix(loggerFactory);
				var cryptOidInfo = unixService.GetHashAlg(signatureAlgOid);
				return cryptOidInfo.Algid;
			}
			else
			{
				log.LogDebug("Получаем алгоритм хэширования под Windows платформой.");

				var winService = new SignServiceWin(loggerFactory);
				var cryptOidInfo = winService.GetHashAlg(signatureAlgOid);
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
			if (IsUnix)
			{
				log.LogError("Отсутствует реализация для Unix системы.");
				throw new Exception("Отсутствует реализация для Unix системы.");
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
