using Microsoft.Extensions.Logging;
using SignOVService.Model.Cryptography;
using SignOVService.Model.Smev.Sign;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

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

		/// <summary>
		/// Метод поиска сертификата в хранилище по указанному отпечатку
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		X509Certificate2 FindCertificate(string thumbprint)
		{
			log.LogDebug($"Пытаемся получить сертификат из хранилища по отпечатку: {thumbprint}.");
			log.LogDebug($"Тип хранилища: My. Локация: {certificateLocation}.");

			List<X509Store> stores = new List<X509Store>()
			{
				//My
				new X509Store(StoreName.My, StoreLocation.CurrentUser),
				new X509Store(StoreName.My, StoreLocation.LocalMachine),
				//AddressBook
				new X509Store(StoreName.AddressBook, StoreLocation.CurrentUser),
				new X509Store(StoreName.AddressBook, StoreLocation.LocalMachine),
				//AuthRoot
				new X509Store(StoreName.AuthRoot, StoreLocation.CurrentUser),
				new X509Store(StoreName.AuthRoot, StoreLocation.LocalMachine),
				//CertificateAuthority
				new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser),
				new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine),
				//Disallowed
				new X509Store(StoreName.Disallowed, StoreLocation.CurrentUser),
				new X509Store(StoreName.Disallowed, StoreLocation.LocalMachine),
				//Root
				new X509Store(StoreName.Root, StoreLocation.CurrentUser),
				new X509Store(StoreName.Root, StoreLocation.LocalMachine),
				//TrustedPeople
				new X509Store(StoreName.TrustedPeople, StoreLocation.CurrentUser),
				new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine),
				//TrustedPublisher
				new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser),
				new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine)
			};

			List<X509Store> certStores = new List<X509Store>();

			foreach (var item in stores)
			{
				if(item.Certificates.Count > 0)
				{
					certStores.Add(item);
				}
			}

			FIND_TEST(thumbprint, StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint);

			using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
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

		/**<summary>Поиск сертификата (первого удовлетворяющего критериям поиска)</summary>
		* <param name="findType">Тип поиска</param>
		* <param name="findValue">Значение поиска (отпечаток либо серийный номер)</param>
		* <param name="storeLocation">Место </param>
		* <param name="storeName">Имя хранилища</param>
		* <returns>Сертификат</returns>
		* **/
		public X509Certificate2 FIND_TEST(string findValue, StoreLocation storeLocation, StoreName storeName, X509FindType findType)
		{
			IntPtr handleCert = IntPtr.Zero;
			GCHandle handleFull = new GCHandle();
			IntPtr handleSysStore = IntPtr.Zero;

			try
			{
				//// Открываем хранилище сертификатов
				handleSysStore = CApiLite.CertOpenStore(
					new IntPtr(2),
					0,
					IntPtr.Zero,
					0x4000 | 65536, //CERT_SYSTEM_STORE_CURRENT_USER - 65536
					"My"
				);

				if (handleSysStore == IntPtr.Zero)
				{
					throw new Exception("Ошибка при попытке получить дескриптор открытого хранилища сертификатов.");
				}

				var arData = (fIsLinux) ? Encoding.UTF8.GetBytes(findValue) : Encoding.Unicode.GetBytes(findValue);
				handleFull = GCHandle.Alloc(arData, GCHandleType.Pinned);

				IntPtr handlePrev = IntPtr.Zero;

				// Ищем сертификат в хранилище
				handleCert = CApiLite.CertFindCertificateInStore(
					handleSysStore,             // Дескриптор хранилища, в котором будет осуществлен поиск.
					0,                                                  // Тип зашифрования. В этом поиске не используется.
					0,                                                  // dwFindFlags. Специальный критерий поиска.
					UCConst.CERT_FIND_ANY,                              // Тип поиска. Задает вид поиска, который будет
																		/*handleFull.AddrOfPinnedObject()*/IntPtr.Zero,     // pvFindPara. Выдает определенное значение поиска
					handlePrev                                          // pCertContext равен NULL == IntPtr.Zero для первого вызова
				);

				// Освобождаем предыдущий TODO: для циклического обхода
				if (handlePrev != IntPtr.Zero) CApiLite.CertFreeCertificateContext(handlePrev);
				handleFull.Free();

				return (fIsLinux) ? new X509Certificate2(new X509Certificate(handleCert)) : new X509Certificate2(handleCert);
			}
			catch (Exception ex)
			{
				throw new Exception("Неопределенная ошибка при попытке найти сертификат в хранилище. " + ex.Message);
			}
		}

		//TODO: delete
		public static bool fIsLinux
		{
			get
			{
				int iPlatform = (int)Environment.OSVersion.Platform;
				return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
			}
		}
	}
}
