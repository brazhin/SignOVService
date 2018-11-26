using Microsoft.Extensions.Logging;
using SignOVService.Model.Cryptography;
using SignOVService.Model.Smev.Sign;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model
{
	public class SignOVServiceClient
	{
		private readonly X509Certificate2Custom certificate = null;
		private readonly ILogger<SignOVServiceClient> log;
		//private readonly StoreLocation certificateLocation;
		private readonly ILoggerFactory loggerFactory;
		private readonly CryptoProvider crypto;

		public SignOVServiceClient(ILoggerFactory loggerFactory, string storeLocation, string thumbprint)
		{
			this.log = loggerFactory.CreateLogger<SignOVServiceClient>();
			this.loggerFactory = loggerFactory;

			crypto = new CryptoProvider();

			//certificateLocation = (storeLocation.ToLower() == "currentuser") ? StoreLocation.CurrentUser : StoreLocation.LocalMachine;
			//certificate = crypto.FindCertificate(thumbprint);
		}

		/// <summary>
		/// Метод подписания запроса
		/// </summary>
		/// <param name="request"></param>
		/// <returns></returns>
		public string SignOV(RequestSignOV request)
		{
			if (request == null)
			{
				log.LogError("Не удалось получить содержимое запроса на подписание.");
				throw new ArgumentNullException("Не удалось получить содержимое запроса на подписание. " +
					"Убедитесь в правильности формирования запроса."
				);
			}

			var currentCertificate = certificate;

			if (!string.IsNullOrEmpty(request.Thumbprint))
			{
				log.LogDebug($"В запросе указано значение отпечатка {request.Thumbprint}. Запускаем поиск в хранилище.");
				currentCertificate = crypto.FindX509Certificate2(request.Thumbprint);
			}

			if (currentCertificate == null)
			{
				log.LogError("Сертификат, указанный в настройках не найден в хранилище сертификатов.");
				throw new NullReferenceException("Сертификат, указанный в настройках не найден в хранилище сертификатов.");
			}

			string signXml = string.Empty;

			try
			{
				var signSoap = new SignSoapImpl(loggerFactory, currentCertificate, request.Mr);

				XmlDocument xDoc = new XmlDocument();
				xDoc.LoadXml(request.Soap);
				xDoc = signSoap.SignSoapOV(xDoc);
				signXml = xDoc.OuterXml;
			}
			catch (Exception ex)
			{
				log.LogError(ex.Message);
				throw ex;
			}

			return signXml;
		}
	}
}
