using Microsoft.Extensions.Logging;
using SignOVService.Model.Smev.Sign;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model
{
	public class SignOVServiceClient
	{
		private readonly X509Certificate2 certificate;
		private readonly ILogger<SignOVServiceClient> log;
		private readonly StoreLocation certificateLocation;

		public SignOVServiceClient(ILoggerFactory loggerFactory, string storeLocation, string thumbprint)
		{
			this.log = loggerFactory.CreateLogger<SignOVServiceClient>();

			certificateLocation = (storeLocation.ToLower() == "currentuser") ? StoreLocation.CurrentUser : StoreLocation.LocalMachine;
			certificate = FindCertificate(thumbprint);
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

			X509Certificate2 currentCertificate = certificate;

			if (!string.IsNullOrEmpty(request.Thumbprint))
			{
				log.LogDebug($"В запросе указано значение отпечатка {request.Thumbprint}. Запускаем поиск в хранилище.");
				currentCertificate = FindCertificate(request.Thumbprint);
			}

			if (currentCertificate == null)
			{
				log.LogError("Сертификат, указанный в настройках не найден в хранилище сертификатов.");
				throw new NullReferenceException("Сертификат, указанный в настройках не найден в хранилище сертификатов.");
			}

			string signXml = string.Empty;

			try
			{
				var signSoap = new SignSoapImpl(currentCertificate, request.Mr);

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

		/// <summary>
		/// Метод поиска сертификата в хранилище по указанному отпечатку
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		X509Certificate2 FindCertificate(string thumbprint)
		{
			log.LogDebug($"Пытаемся получить сертификат из хранилища по отпечатку: {thumbprint}.");
			log.LogDebug($"Тип хранилища: My. Локация: {certificateLocation}.");

			using (var store = new X509Store(StoreName.My, certificateLocation))
			{
				log.LogDebug("Открываем хранилище сертификатов.");

				store.Open(OpenFlags.ReadOnly);

				log.LogDebug("Ищем сертификат по заданному отпечатку.");

				var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

				log.LogDebug("Закрываем хранилище сертификатов.");

				// Если сертификат найден вернем его из метода
				return (certs.Count > 0) ? certs[0] : null;
			}
		}
	}
}
