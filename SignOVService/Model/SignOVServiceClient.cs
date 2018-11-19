using Microsoft.Extensions.Logging;
using SignOVService.Model.Cryptography;
using SignOVService.Model.Smev.Sign;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using static SignOVService.Model.Cryptography.CApiLite;

namespace SignOVService.Model
{
	public class SignOVServiceClient
	{
		private readonly X509Certificate2 certificate;
		private readonly ILogger<SignOVServiceClient> log;
		private readonly StoreLocation certificateLocation;
		private readonly ILoggerFactory loggerFactory;

		public SignOVServiceClient(ILoggerFactory loggerFactory, string storeLocation, string thumbprint)
		{
			this.log = loggerFactory.CreateLogger<SignOVServiceClient>();
			this.loggerFactory = loggerFactory;

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

		/**<summary>Поиск сертификата (первого удовлетворяющего критериям поиска)</summary>
		* <param name="findValue">Значение поиска (отпечаток)</param>
		* <returns>Сертификат</returns>
		* TODO: добавить логи в метод
		*/
		public X509Certificate2 FindCertificate(string findValue)
		{
			// Дескриптор сертификата (по умолчанию 0)
			IntPtr handleCert = IntPtr.Zero;
			// Дескриптор системного хранилища сертификатов (по умолчанию 0)
			IntPtr handleSysStore = IntPtr.Zero;

			try
			{
				// Открываем хранилище сертификатов
				handleSysStore = CApiLite.CertOpenStore(
					UCConst.CERT_STORE_PROV_SYSTEM,
					0,
					IntPtr.Zero,
					65536, //CurrentUser
					"MY"
				);

				if (handleSysStore == IntPtr.Zero)
				{
					log.LogError("Ошибка при попытке открыть хранилище сертификатов. Не удалось получить дескриптор открытого хранилища.");
					throw new Exception("Ошибка при попытке открыть хранилище сертификатов. Не удалось получить дескриптор открытого хранилища.");
				}

				// Получаем значение thumbprint в бинарном виде
				var sha1hash = StringToByteArray(findValue);

				// Формируем объект CRYPT_HASH_BLOB в памяти. 
				// Данный объект несет информацию об thumbprint для поиска по флагу CERT_FIND_SHA1_HASH (поиск по отпечатку)
				CRYPT_HASH_BLOB hashb = new CRYPT_HASH_BLOB();
				hashb.pbData = Marshal.AllocHGlobal(sha1hash.Length);
				Marshal.Copy(sha1hash, 0, hashb.pbData, sha1hash.Length);
				hashb.cbData = sha1hash.Length;

				// Ищем сертификат в хранилище
				handleCert = CApiLite.CertFindCertificateInStore(
					handleSysStore,
					UCConst.PKCS_7_OR_X509_ASN_ENCODING,
					0,
					UCConst.CERT_FIND_SHA1_HASH,
					ref hashb,
					IntPtr.Zero
				);

				if(handleCert == IntPtr.Zero)
				{
					log.LogError($"Сертификат со значением thumbprint = {findValue} не найден в хранилище сертификатов.");
					throw new Exception($"Сертификат со значением thumbprint = {findValue} не найден в хранилище сертификатов.");
				}

				// Получаем контекст сертификата для дальнейшего преобразования к объекту X509Certificate2
				CERT_CONTEXT contextCert = (CERT_CONTEXT)Marshal.PtrToStructure(handleCert, typeof(CERT_CONTEXT));

				// Если в Linux получаем объект X509Certificate2 из contextCert.pbCertEncoded
				// иначе создаем на основе дескриптора
				if (IsLinux)
				{
					byte[] certBin = new byte[contextCert.cbCertEncoded];
					Marshal.Copy(contextCert.pbCertEncoded, certBin, 0, certBin.Length);

					return new X509Certificate2(certBin);
				}

				return new X509Certificate2(handleCert);
			}
			catch (Exception ex)
			{
				log.LogError("Неопределенная ошибка при попытке найти сертификат в хранилище. " + ex.Message);
				throw new Exception("Неопределенная ошибка при попытке найти сертификат в хранилище. " + ex.Message);
			}
			finally
			{
				CertCloseStore(handleSysStore, 0);
				CertFreeCertificateContext(handleCert);
			}
		}

		/// <summary>
		/// Свойство для определения ОС на которой развернут сервис
		/// </summary>
		private bool IsLinux
		{
			get
			{
				int iPlatform = (int)Environment.OSVersion.Platform;
				return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
			}
		}

		/// <summary>
		/// Метод преобразования hex строки в массив байт,
		/// Необходим для правильного преобразования в байта значения thumbprint сертификата
		/// </summary>
		/// <param name="hex"></param>
		/// <returns></returns>
		private byte[] StringToByteArray(string hex)
		{
			int NumberChars = hex.Length;
			byte[] bytes = new byte[NumberChars / 2];

			for (int i = 0; i < NumberChars; i += 2)
			{
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}

			return bytes;
		}
	}
}
