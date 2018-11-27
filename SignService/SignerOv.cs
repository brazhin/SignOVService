using Microsoft.Extensions.Logging;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static SignService.CApiExtConst;

namespace SignService
{
	/// <summary>
	/// Класс реализующий подписание данных.
	/// </summary>
	public class SignerOv
	{
		private ILogger<SignerOv> log;

		public SignerOv(ILogger<SignerOv> log)
		{
			this.log = log;
		}

		/// <summary>
		/// Свойство определяет текущую ОС
		/// </summary>
		private static bool IsLinux
		{
			get
			{
				int iPlatform = (int)Environment.OSVersion.Platform;
				return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
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
			if (string.IsNullOrEmpty(thumbprint))
			{
				throw new NullReferenceException("Ошибка при попытке получить значение thumbprint. Отсутствует значение.");
			}

			if(data == null || data.Length <= 0)
			{
				throw new NullReferenceException("Ошибка при попытке получить данные на подпись. Отсутствует значение.");
			}

			if(log == null)
			{
				throw new NullReferenceException("Метод Sign использует логгирование. Ошибка при попытке получить ссылку на экземпляр Логгера.");
			}

			IntPtr hCert = FindCertificate(thumbprint);
			return Sign(data, hCert);
		}

		/// <summary>
		/// Метод проверки ЭЦП
		/// </summary>
		/// <param name="sign"></param>
		/// <returns></returns>
		//public bool VerifyDetachedMessageSignature(byte[] sign)
		//{
		//	CRYPT_VERIFY_MESSAGE_PARA param = new CRYPT_VERIFY_MESSAGE_PARA
		//	{
		//		cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_VERIFY_MESSAGE_PARA)),
		//		dwMsgAndCertEncodingType = PKCS_7_OR_X509_ASN_ENCODING,
		//		hCryptProv = IntPtr.Zero,
		//		pfnGetSignerCertificate = null
		//	};

		//	return false;
		//}

		/// <summary>
		/// Метод подписи данных с использованием КриптоApi
		/// </summary>
		/// <param name="data"></param>
		/// <param name="hCert"></param>
		/// <returns></returns>
		private byte[] Sign(byte[] data, IntPtr hCert)
		{
			log.LogDebug("Пытаемся выполнить метод подписи данных.");
			log.LogDebug("Заполняем структуру данных содержащую основные параметры необходимые для подписи.");

			// Структура содержит информацию для подписания сообщений с использованием указанного контекста сертификата подписи
			CRYPT_SIGN_MESSAGE_PARA pParams = new CRYPT_SIGN_MESSAGE_PARA
			{
				// Размер этой структуры в байтах
				cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_SIGN_MESSAGE_PARA)),
				// Используемый тип кодирования
				dwMsgEncodingType = CApiExtConst.PKCS_7_OR_X509_ASN_ENCODING,
				// Указатель на CERT_CONTEXT, который будет использоваться при подписании. 
				// Для того чтобы контекст предоставил доступ к закрытому сигнатурному ключу,
				// необходимо установить свойство CERT_KEY_PROV_INFO_PROP_ID или CERT_KEY_CONTEXT_PROP_ID
				pSigningCert = hCert,

				// Количество элементов в rgpMsgCert массиве CERT_CONTEXT структур.Если установлено ноль,
				// в подписанное сообщение не включаются сертификаты.
				cMsgCert = 1
			};

			log.LogDebug($"Пытаемся получить информацию о сертификате.");

			CERT_CONTEXT contextCert = Marshal.PtrToStructure<CERT_CONTEXT>(hCert);
			CERT_INFO certInfo = Marshal.PtrToStructure<CERT_INFO>(contextCert.pCertInfo);

			log.LogDebug("Информация о сертификате успешно получена.");
			log.LogDebug("Пытаемся получить информацию об алгоритме хэширования.");

			//Содержащий алгоритм хеширования, используемый для хеширования данных, подлежащих подписке.
			pParams.HashAlgorithm.pszObjId = GetHashOidByKeyOid(certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId);

			log.LogDebug($"Информацию об алгоритме хэширования успешно получена. HashAlgorithm.pszObjId == {pParams.HashAlgorithm.pszObjId}.");

			// Массив указателей на буферы, содержащие содержимое, подлежащее подписке.
			IntPtr rgpbToBeSigned = Marshal.AllocHGlobal(data.Length);

			// Выделяем память под хранение сертификата
			GCHandle pGC = GCHandle.Alloc(hCert, GCHandleType.Pinned);

			try
			{
				// Массив указателей на контексты сертификатов для включения в подписанное сообщение. 
				// Если хотим использовать сертификат для подписания, указатель на него должен быть в массиве rgpMsgCert.
				pParams.rgpMsgCert = pGC.AddrOfPinnedObject();
				Marshal.Copy(data, 0, rgpbToBeSigned, data.Length);

				// Указатель, определяющий размер в байтах буфера signArray . 
				// Когда функция возвращается, эта переменная содержит размер в байтах подписанного и закодированного сообщения.
				uint signArrayLength = 0;

				// Указатель на буфер , для получения кодированного подписанного хэш, если detached является значение TRUE , 
				// или как кодированного контента и подписанного хэша , если detached является FALSE.
				byte[] signArray = null;

				// TRUE, если это должна быть отдельная подпись, Если для этого параметра установлено значение TRUE , в pbSignedBlob кодируется только подписанный хеш . 
				// В противном случае кодируются как rgpbToBeSigned, так и подписанный хеш.
				bool detached = true;

				// Количество элементов массива в rgpbToBeSigned.
				// Этот параметр должен быть установлен в единицу, если для параметра fDetachedSignature установлено значение TRUE
				uint cToBeSigned = 1;

				try
				{
					log.LogDebug("Пытаемся получить размер для буфера содержащего массив байт подписи.");

					if (IsLinux)
					{
						// Подписываем данные
						// new uint[1] { (uint)data.Length } - Массив размеров в байтах буферов содержимого, на которые указывает rgpbToBeSigned
						if (!CApiExtUnix.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
						{
							throw new CryptographicException("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
						}

						log.LogDebug($"Размер для буфера содержащего массив байт подписи успешно получен. Размер: {signArrayLength}.");
						signArray = new byte[signArrayLength];

						log.LogDebug("Пытаемся подписать данные.");

						if (!CApiExtUnix.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
						{
							throw new CryptographicException("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
						}

						log.LogDebug("Данные успешно подписаны. Возвращаем подпись в виде массива байт.");
					}
					else
					{
						// Подписываем данные
						// new uint[1] { (uint)data.Length } - Массив размеров в байтах буферов содержимого, на которые указывает rgpbToBeSigned
						if (!CApiExtWin.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
						{
							throw new CryptographicException("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
						}

						log.LogDebug($"Размер для буфера содержащего массив байт подписи успешно получен. Размер: {signArrayLength}.");
						signArray = new byte[signArrayLength];

						log.LogDebug("Пытаемся подписать данные.");

						if (!CApiExtWin.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
						{
							throw new CryptographicException("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
						}

						log.LogDebug("Данные успешно подписаны. Возвращаем подпись в виде массива байт.");
					}
				}
				catch (Exception ex)
				{
					log.LogError($"Необработанная ошибка при попытке подписать данные. {ex.Message}.");
					throw ex;
				}

				return signArray;
			}
			catch (Exception ex)
			{
				log.LogError($"Необработанная ошибка при выполнении метода Sign. {ex.Message}.");
				throw ex;
			}
			finally
			{
				try
				{
					log.LogDebug("Пытаемся освободить занимаемую память.");

					Marshal.FreeHGlobal(rgpbToBeSigned);
					pGC.Free();

					log.LogDebug("Освобождение занимаемой памяти выполнено успешно.");
				}
				catch(Exception ex)
				{
					log.LogError($"Ошибка при попытке освободить неуправляемую память. {ex.Message}.");
				}
			}
		}

		/// <summary>
		/// Метод поиска сертификата в хранилище с использованием КриптоApi
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		private IntPtr FindCertificate(string thumbprint)
		{
			IntPtr handleSysStore = IntPtr.Zero;
			IntPtr handleCert = IntPtr.Zero;

			// Формируем параметр для метода поиска
			CRYPT_HASH_BLOB hashb = new CRYPT_HASH_BLOB();

			try
			{
				log.LogDebug($"Пытаемся открыть Личное хранилище сертификатов для Текущего пользователя.");

				// Открываем хранилище сертификатов
				handleSysStore = (IsLinux) ? CApiExtUnix.CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, IntPtr.Zero, 65536, "MY") : 
					CApiExtWin.CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, IntPtr.Zero, 65536, "MY");

				if (handleSysStore == IntPtr.Zero || handleSysStore == null)
				{
					log.LogError("Не удалось открыть хранилище Личное для текущего пользователя. Handler == 0.");
					throw new CryptographicException("Ошибка, не удалось открыть хранилище Личное для текущего пользователя.");
				}

				log.LogDebug($"Личное хранилище сертификатов для Текущего пользователя успешно открыто.");
				log.LogDebug($"Пытаемся преобразовать значение Thumbprint в массив байт.");

				// Получаем значение thumbprint в виде массива байт
				byte[] sha1Hash = HexStringToBinary(thumbprint);

				log.LogDebug("Значение Thumbprint успешно преобразовано в массив байт.");
				log.LogDebug("Пытаемся разместить бинарное значение Thumbprint в неуправляемой памяти.");

				try
				{
					hashb.pbData = Marshal.AllocHGlobal(thumbprint.Length);
					Marshal.Copy(sha1Hash, 0, hashb.pbData, sha1Hash.Length);
					hashb.cbData = sha1Hash.Length;
				}
				catch(Exception ex)
				{
					log.LogError($"Ошибка при попытке разместить значение Thumbprint в неуправляемой памяти. {ex.Message}.");
					Marshal.FreeHGlobal(hashb.pbData);
					throw new CryptographicException($"Ошибка при попытке разместить значение Thumbprint в неуправляемой памяти. {ex.Message}.");
				}

				log.LogDebug("Бинарное значение Thumbprint успешно размещено в неуправляемой памяти.");
				log.LogDebug("Пытаемся найти сертификат по Thumbprint данным в неуправляемой памяти.");

				// Ищем сертификат в хранилище
				handleCert = (IsLinux) ?
					CApiExtUnix.CertFindCertificateInStore(handleSysStore, PKCS_7_OR_X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, ref hashb, IntPtr.Zero) :
					CApiExtWin.CertFindCertificateInStore(handleSysStore, PKCS_7_OR_X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, ref hashb, IntPtr.Zero);

				if (handleCert == IntPtr.Zero || handleCert == null)
				{
					log.LogError("Ошибка при попытке получить дескриптор сертификата. Handler == 0.");
					throw new CryptographicException("Ошибка при попытке получить дескриптор сертификата.");
				}

				log.LogDebug("Пытаемся получить дубликат сертификата.");
				var hCert = (IsLinux) ? CApiExtUnix.CertDuplicateCertificateContext(handleCert) : CApiExtWin.CertDuplicateCertificateContext(handleCert);

				if (hCert == IntPtr.Zero || hCert == null)
				{
					log.LogError("Ошибка при попытке получить дубликат сертификата. Handle == 0.");
					throw new CryptographicException("Ошибка при попытке получить дубликат сертификата.");
				}

				log.LogDebug("Дубликат сертификата успешно получен. Возвращаем его в качестве результата.");

				return hCert;
			}
			catch(Exception ex)
			{
				log.LogError($"Необработанная ошибка в методе FindCertificate: {ex.Message}.");
				throw ex;
			}
			finally
			{
				try
				{
					log.LogDebug("Пытаемся очистить область неуправляемой памяти выделенной под байт массив Thumbprint.");
					Marshal.FreeHGlobal(hashb.pbData);
					log.LogDebug("область неуправляемой памяти выделенной под байт массив Thumbprint успешно очищена.");

					log.LogDebug("Пытаемся очистить контекст сертификата.");

					if (IsLinux)
						CApiExtUnix.CertFreeCertificateContext(handleCert);
					else
						CApiExtWin.CertFreeCertificateContext(handleCert);

					log.LogDebug("Контекст сертификата успешно очищен.");
				}
				catch(Exception ex)
				{
					log.LogError($"Ошибка при попытке очистить контекст сертификата: {ex.Message}.");
				}

				try
				{
					log.LogDebug("Пытаемся закрыть хранилище сертификатов.");

					if(IsLinux)
						CApiExtUnix.CertCloseStore(handleSysStore, 0);
					else
						CApiExtWin.CertCloseStore(handleSysStore, 0);

					log.LogDebug("Хранилище сертификатов успешно закрыто.");
				}
				catch(Exception ex)
				{
					log.LogError($"Ошибка при попытке закрыть хранилище сертификатов: {ex.Message}.");
				}
			}
		}

		/// <summary>
		/// Метод преобразования hex строки в массив байт (для преобразования значения thumbprint)
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		private byte[] HexStringToBinary(string thumbprint)
		{
			byte[] bytes = new byte[thumbprint.Length / 2];

			for (int i = 0; i < thumbprint.Length; i += 2)
			{
				bytes[i / 2] = Convert.ToByte(thumbprint.Substring(i, 2), 16);
			}

			return bytes;
		}

		/// <summary>
		/// Метод получения значения HashOid по Oid алгоритму публичного ключа
		/// </summary>
		/// <param name="szKeyOid"></param>
		/// <returns></returns>
		private string GetHashOidByKeyOid(string szKeyOid)
		{
			if (szKeyOid == szOID_CP_GOST_R3410EL)
			{
				return szOID_CP_GOST_R3411;
			}
			else if (szKeyOid == szOID_CP_GOST_R3410_12_256)
			{
				return szOID_CP_GOST_R3411_12_256;
			}
			else if (szKeyOid == szOID_CP_GOST_R3410_12_512)
			{
				return szOID_CP_GOST_R3411_12_512;
			}

			return null;
		}
	}
}
