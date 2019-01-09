using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Smev.SoapSigners;
using SignService.Win.Api;
using SignService.Win.Gost;
using SignService.Win.Utils;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using static SignService.CApiExtConst;

namespace SignService.Win
{
	/// <summary>
	/// Класс реализующий выполнение криптографических операций под Windows платформой
	/// </summary>
	internal class SignServiceWin
	{
		private ILoggerFactory loggerFactory;
		private readonly ILogger<SignServiceWin> log;

		public SignServiceWin(ILoggerFactory loggerFactory)
		{
			this.loggerFactory = loggerFactory;
			this.log = loggerFactory.CreateLogger<SignServiceWin>();
		}

		/// <summary>
		/// Метод получения алгоритма хэширования
		/// </summary>
		/// <param name="signatureAlgOid"></param>
		/// <returns></returns>
		internal static CRYPT_OID_INFO GetHashAlg(string signatureAlgOid)
		{
			IntPtr sigId = CApiExtWin.CryptFindOIDInfo(OidKeyType.Oid, signatureAlgOid, OidGroup.SignatureAlgorithm);
			CRYPT_OID_INFO CertInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(sigId);

			uint alg = CertInfo.Algid;

			IntPtr int_addr = Marshal.AllocHGlobal(Marshal.SizeOf(alg));
			Marshal.WriteInt32(int_addr, (int)alg);

			// Получаем информацию об алгоритме хэш
			IntPtr hass = CApiExtWin.CryptFindOIDInfo(OidKeyType.AlgorithmID, int_addr, OidGroup.HashAlgorithm);
			CRYPT_OID_INFO hassInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(hass);

			if (hass == IntPtr.Zero)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return hassInfo;
		}

		/// <summary>
		/// Метод подписи XML
		/// </summary>
		/// <param name="xml"></param>
		/// <param name="mr"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		internal string SignSoap(string xml, Mr mr, string thumbprint, string password)
		{
			log.LogDebug($"Пытаемся получить объект для выполнения подписи согласно версии МР: {mr}.");
			var signer = SignerSoapHelper.CreateSigner(mr, loggerFactory);

			var doc = new XmlDocument();

			try
			{
				log.LogDebug("Пытаемся распарсить входящий XML.");
				doc.LoadXml(xml);
			}
			catch (Exception ex)
			{
				log.LogError($"Ошибка при парсинге XML содержимого в запросе. {ex.Message}.");
				throw new CryptographicException($"Ошибка при парсинге XML содержимого в запросе. {ex.Message}.");
			}

			log.LogDebug($"Пытаемся найти сертификат с указанным thumbprint: {thumbprint}.");
			var certHandle = FindCertificate(thumbprint);

			var signedXml = signer.SignMessageAsOv(doc, certHandle, password);
			return signedXml.OuterXml;
		}

		/// <summary>
		/// Метод получения хэш
		/// </summary>
		/// <param name="data"></param>
		/// <param name="algId"></param>
		/// <returns></returns>
		internal string GetHashBySigAlgId(Stream data, uint algId)
		{
			log.LogDebug("Запущен метод получения хэш под Windows платформой.");

			byte[] hashResult = null;

			if (algId == CApiExtConst.GOST341194)
			{
				log.LogDebug($"Полученный алгоритм хэширования {algId} соответствует ГОСТ-2001");
				HashAlgorithm hash = new HashAlgGost2001Win();
				hashResult = hash.ComputeHash(data);
			}
			else if(algId == CApiExtConst.GOST2012_256)
			{
				log.LogDebug($"Полученный алгоритм хэширования {algId} соответствует ГОСТ-2012-256");
				var hash = new HashAlgGost2012_256Win();
				hashResult = hash.ComputeHash(data);
			}
			else if(algId == CApiExtConst.GOST2012_512)
			{
				log.LogDebug($"Полученный алгоритм хэширования {algId} соответствует ГОСТ-2012-512");
				var hash = new HashAlgGost2012_512Win();
				hashResult = hash.ComputeHash(data);
			}
			else
			{
				log.LogError($"Полученный алгоритм хэширования {algId} не соответствует поддерживаемым ГОСТ алгоритмам.");
				throw new Exception($"Полученный алгоритм хэширования {algId} не соответствует поддерживаемым ГОСТ алгоритмам.");
			}

			if (hashResult == null || hashResult.Length <= 0)
			{
				log.LogError("Не удалось вычислить хэш. Отсутствует значение.");
				throw new CryptographicException("Ошибка при получении хэш.");
			}

			log.LogDebug($"Хэш получен. Преобразуем в Hex строку.");

			var hexStr = SignServiceUtils.ConvertByteToHex(hashResult);

			log.LogDebug("Преобразование выполнено успешно.");

			return hexStr;
		}

		/// <summary>
		/// Метод получения списка доверенных сертификатов
		/// </summary>
		/// <returns></returns>
		internal X509Certificate2Collection GetTrustedCertificates()
		{
			log.LogDebug("Пытаемся получить доступ к хранилищу доверенных сертификатов текущего пользователя.");
			using(var store = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser))
			{
				log.LogDebug("Пытаемся открыть хранилище доверенных издателей текущего пользователя.");
				store.Open(OpenFlags.ReadOnly);
				log.LogDebug("Пытаемся получить список сертификатов.");
				var certificates = store.Certificates;
				store.Close();

				log.LogDebug("Список доверенных издателей успешно получен.");

				return certificates;
			}
		}

		/// <summary>
		/// Метод проверки подписи
		/// </summary>
		/// <param name="messageData"></param>
		/// <param name="signatureData"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal bool VerifyDetachedMessage(byte[] signatureData, byte[] messageData, bool isCheckTrusted, ref X509Certificate2 certFromSign)
		{
			log.LogDebug("Запущен метод проверки открепленной подписи под Windows платформой.");

			// Заполняем буфер с информацией о данных на основе которых получена подпись
			IntPtr messagePtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(byte)) * messageData.Length);
			Marshal.Copy(messageData, 0, messagePtr, messageData.Length);
			IntPtr[] rgpbToBeSigned = new IntPtr[1] { messagePtr };
			int[] rgcbToBeSigned = new int[1] { messageData.Length };
			GCHandle pCertContext = GCHandle.Alloc(IntPtr.Zero, GCHandleType.Pinned);

			CRYPT_VERIFY_MESSAGE_PARA verifyParams = new CRYPT_VERIFY_MESSAGE_PARA()
			{
				cbSize = (int)Marshal.SizeOf(typeof(CRYPT_VERIFY_MESSAGE_PARA)),
				dwMsgAndCertEncodingType = PKCS_7_OR_X509_ASN_ENCODING,
				hCryptProv = 0,
				pfnGetSignerCertificate = IntPtr.Zero,
				pvGetArg = IntPtr.Zero
			};

			try
			{
				log.LogDebug("Выполняем проверку открепленной подписи используя метод CryptVerifyDetachedMessageSignature.");

				bool result = CApiExtWin.CryptVerifyDetachedMessageSignature(
					ref verifyParams, // Verify parameters.
					0, // Signer index.
					signatureData, // Buffer for decoded message.
					signatureData.Length, // Size of buffer.
					1,
					rgpbToBeSigned, // Pointer to signed BLOB.
					rgcbToBeSigned, // Size of signed BLOB.
					pCertContext.AddrOfPinnedObject()
				);

				if (!result)
				{
					log.LogError($"Метод проверки подписи CryptVerifyDetachedMessageSignature вернул ошибку. Статус код ошибки: {Marshal.GetLastWin32Error()}.");
					return result;
				}

				log.LogDebug($"Метод CryptVerifyDetachedMessageSignature вернул true. Пытаемся получить сертификат из подписи.");

				try
				{
					log.LogDebug($"Флаг проверки сертификата в списке доверенных издателей {(isCheckTrusted ? "установлен" : "не установлен")}");

					// Информацию о сертификате из подписи можно получить только если проверка вернула true, иначе возникнет исключение
					certFromSign = new X509Certificate2((IntPtr)pCertContext.Target);

					if (isCheckTrusted)
					{
						log.LogDebug("Сертификат из подписи успешно получен. Проверяем наличие сертификата в списке доверенных издателей.");

						var trustedCerts = GetTrustedCertificates();

						if (trustedCerts.Count <= 0)
						{
							log.LogError("Список доверенных издателей пуст. Отсутствует доверие к сертификату.");
							return false;
						}

						if (!trustedCerts.Contains(certFromSign))
						{
							log.LogError("Сертификат указанный в подписи не найден среди доверенных издателей.");
							return false;
						}
					}
				}
				catch(Exception ex)
				{
					log.LogError($"Необработанная ошибка при попытке проверить сертификат из подписи на наличие в списке доверенных. {ex.Message}.");
					return false;
				}
				finally
				{
					CApiExtWin.CertFreeCertificateContext((IntPtr)pCertContext.Target);
				}

				log.LogDebug("Проверка выполнена. Подпись корректна.");

				return result;
			}
			finally
			{
				pCertContext.Free();
			}
		}

		/// <summary>
		/// Метод подписи данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal byte[] Sign(byte[] data, string thumbprint, string password)
		{
			IntPtr hCert = FindCertificate(thumbprint);
			return Sign(data, hCert, password);
		}

		/// <summary>
		/// Метод поиска сертификата в личном хранилище, текущего пользователя
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal IntPtr FindCertificate(string thumbprint)
		{
			IntPtr handleSysStore = IntPtr.Zero;
			IntPtr handleCert = IntPtr.Zero;

			// Формируем параметр для метода поиска
			CApiExtConst.CRYPT_HASH_BLOB hashb = new CApiExtConst.CRYPT_HASH_BLOB();

			try
			{
				log.LogDebug($"Пытаемся открыть 'MY' хранилище сертификатов для Текущего пользователя.");

				// Открываем хранилище сертификатов
				handleSysStore = CApiExtWin.CertOpenStore(CApiExtConst.CERT_STORE_PROV_SYSTEM, 0, IntPtr.Zero, CApiExtConst.CURRENT_USER, "MY");

				if (handleSysStore == IntPtr.Zero || handleSysStore == null)
				{
					log.LogError("Не удалось открыть хранилище 'MY' для текущего пользователя.");
					throw new CryptographicException("Ошибка, не удалось открыть хранилище 'MY' для текущего пользователя.");
				}

				log.LogDebug($"Личное хранилище сертификатов для Текущего пользователя успешно открыто.");
				log.LogDebug($"Пытаемся преобразовать значение Thumbprint в массив байт.");

				// Получаем значение thumbprint в виде массива байт
				byte[] sha1Hash = SignServiceUtils.HexStringToBinary(thumbprint);

				log.LogDebug("Значение Thumbprint успешно преобразовано в массив байт.");
				log.LogDebug("Пытаемся разместить бинарное значение Thumbprint в неуправляемой памяти.");

				try
				{
					hashb.pbData = Marshal.AllocHGlobal(thumbprint.Length);
					Marshal.Copy(sha1Hash, 0, hashb.pbData, sha1Hash.Length);
					hashb.cbData = sha1Hash.Length;
				}
				catch (Exception ex)
				{
					log.LogError($"Ошибка при попытке разместить значение Thumbprint в неуправляемой памяти. {ex.Message}.");
					Marshal.FreeHGlobal(hashb.pbData);
					throw new CryptographicException($"Ошибка при попытке разместить значение Thumbprint в неуправляемой памяти. {ex.Message}.");
				}

				log.LogDebug("Бинарное значение Thumbprint успешно размещено в неуправляемой памяти.");
				log.LogDebug("Пытаемся найти сертификат по Thumbprint данным в неуправляемой памяти.");

				// Ищем сертификат в хранилище
				handleCert = CApiExtWin.CertFindCertificateInStore(handleSysStore, CApiExtConst.PKCS_7_OR_X509_ASN_ENCODING, 0, CApiExtConst.CERT_FIND_SHA1_HASH, ref hashb, IntPtr.Zero);

				if (handleCert == IntPtr.Zero || handleCert == null)
				{
					log.LogError("Ошибка при получении дескриптора сертификата из хранилища 'MY', для текущего пользователя.");
					throw new CryptographicException("Ошибка при получении дескриптора сертификата из хранилища 'MY', для текущего пользователя.");
				}

				return handleCert;
			}
			finally
			{
				Marshal.FreeHGlobal(hashb.pbData);
				CApiExtWin.CertCloseStore(handleSysStore, 0);
			}
		}

		/// <summary>
		/// Метод реализующий подписание данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="hCert"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static byte[] Sign(byte[] data, IntPtr hCert, string password)
		{
			// Структура содержит информацию для подписания сообщений с использованием указанного контекста сертификата подписи
			CApiExtConst.CRYPT_SIGN_MESSAGE_PARA pParams = new CApiExtConst.CRYPT_SIGN_MESSAGE_PARA
			{
				// Размер этой структуры в байтах
				cbSize = (uint)Marshal.SizeOf(typeof(CApiExtConst.CRYPT_SIGN_MESSAGE_PARA)),
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

			CApiExtConst.CERT_CONTEXT contextCert = Marshal.PtrToStructure<CApiExtConst.CERT_CONTEXT>(hCert);
			CApiExtConst.CERT_INFO certInfo = Marshal.PtrToStructure<CApiExtConst.CERT_INFO>(contextCert.pCertInfo);

			var signatureAlg = SignServiceUtils.GetSignatureAlg(certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId);
			var cryptOidInfo = GetHashAlg(signatureAlg);

			//Содержащий алгоритм хеширования, используемый для хеширования данных, подлежащих подписке.
			pParams.HashAlgorithm.pszObjId = cryptOidInfo.pszOID;

			// Массив указателей на буферы, содержащие содержимое, подлежащее подписке.
			IntPtr rgpbToBeSigned = Marshal.AllocHGlobal(data.Length);

			// Выделяем память под хранение сертификата
			GCHandle pGC = GCHandle.Alloc(hCert, GCHandleType.Pinned);
			IntPtr cspHandle = IntPtr.Zero;

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

				// Обращаемся к csp с установкой связи с контейнером и установкой пароля, 
				// т.к в csp установлен флаг кэширования при вызове метода CryptSignMessage будет использован csp с установленным паролем
				uint keySpec = CApiExtConst.AT_SIGNATURE;
				cspHandle = Win32ExtUtil.GetHandler(hCert, out keySpec, password);

				// Подписываем данные
				// new uint[1] { (uint)data.Length } - Массив размеров в байтах буферов содержимого, на которые указывает rgpbToBeSigned
				if (!CApiExtWin.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
				{
					throw new CryptographicException($"Ошибка при подписании данных. Первый вызов CryptSignMessage вернул false. Код ошибки: {Marshal.GetLastWin32Error()}.");
				}

				signArray = new byte[signArrayLength];

				if (!CApiExtWin.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
				{
					throw new CryptographicException($"Ошибка при подписании данных. Второй вызов CryptSignMessage вернул false. Код ошибки: {Marshal.GetLastWin32Error()}.");
				}

				return signArray;
			}
			finally
			{
				SignServiceUtils.ReleaseProvHandle(cspHandle);
				Marshal.FreeHGlobal(rgpbToBeSigned);
				pGC.Free();
			}
		}
	}
}
