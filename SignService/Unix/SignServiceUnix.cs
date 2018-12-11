using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Smev.XmlSigners;
using SignService.Unix.Api;
using SignService.Unix.Gost;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using static SignService.CApiExtConst;

namespace SignService.Unix
{
	/// <summary>
	/// Класс реализующий выполнение криптографических операций под Unix платформой
	/// </summary>
	internal class SignServiceUnix
	{
		private ILoggerFactory loggerFactory;
		private readonly ILogger<SignServiceUnix> log;

		internal SignServiceUnix(ILoggerFactory loggerFactory)
		{
			this.loggerFactory = loggerFactory;
			this.log = loggerFactory.CreateLogger<SignServiceUnix>();
		}

		/// <summary>
		/// Метод подписи xml
		/// </summary>
		/// <param name="xml"></param>
		/// <param name="mr"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		internal string SignXml(string xml, Mr mr, string thumbprint)
		{
			var signer = SignerXmlHelper.CreateSigner(mr, loggerFactory);

			var doc = new XmlDocument();
			doc.LoadXml(xml);

			var certHandle = FindCertificate(thumbprint);

			var signedXml = signer.SignMessageAsOv(doc, certHandle);
			return signedXml.OuterXml;
		}

		/// <summary>
		/// Метод поиска сертификата в личном хранилище, текущего пользователя
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		internal IntPtr FindCertificate(string thumbprint)
		{
			IntPtr handleSysStore = IntPtr.Zero;
			IntPtr handleCert = IntPtr.Zero;

			// Формируем параметр для метода поиска
			CApiExtConst.CRYPT_HASH_BLOB hashb = new CApiExtConst.CRYPT_HASH_BLOB();

			try
			{
				log.LogDebug($"Пытаемся открыть Личное хранилище сертификатов для Текущего пользователя.");

				// Открываем хранилище сертификатов
				handleSysStore = CApiExtUnix.CertOpenStore(CApiExtConst.CERT_STORE_PROV_SYSTEM, 0, IntPtr.Zero, CApiExtConst.CURRENT_USER, "MY");

				if (handleSysStore == IntPtr.Zero || handleSysStore == null)
				{
					log.LogError("Не удалось открыть хранилище Личное для текущего пользователя. Handler == 0.");
					throw new CryptographicException("Ошибка, не удалось открыть хранилище Личное для текущего пользователя.");
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
				handleCert = CApiExtUnix.CertFindCertificateInStore(handleSysStore, CApiExtConst.PKCS_7_OR_X509_ASN_ENCODING, 0, CApiExtConst.CERT_FIND_SHA1_HASH, ref hashb, IntPtr.Zero);

				if (handleCert == IntPtr.Zero || handleCert == null)
				{
					log.LogError("Ошибка при попытке получить дескриптор сертификата. Handler == 0.");
					throw new CryptographicException("Ошибка при попытке получить дескриптор сертификата.");
				}

				log.LogDebug("Пытаемся получить дубликат сертификата.");
				var hCert = CApiExtUnix.CertDuplicateCertificateContext(handleCert);

				if (hCert == IntPtr.Zero || hCert == null)
				{
					log.LogError("Ошибка при попытке получить дубликат сертификата. Handle == 0.");
					throw new CryptographicException("Ошибка при попытке получить дубликат сертификата.");
				}

				log.LogDebug("Дубликат сертификата успешно получен. Возвращаем его в качестве результата.");

				return hCert;
			}
			finally
			{
				Marshal.FreeHGlobal(hashb.pbData);
				CApiExtUnix.CertFreeCertificateContext(handleCert);
				CApiExtUnix.CertCloseStore(handleSysStore, 0);
			}
		}

		/// <summary>
		/// Метод подписи данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		internal byte[] Sign(byte[]data, string thumbprint)
		{
			IntPtr hCert = FindCertificate(thumbprint);
			return Sign(data, hCert);
		}

		/// <summary>
		/// Метод проверки открепленной подписи
		/// </summary>
		/// <returns></returns>
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

				bool result = CApiExtUnix.CryptVerifyDetachedMessageSignature(
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

					// При создании X509Certificate2 под Linux, пришлось использовать приведение хэндлера сертификата к структуре CERT_CONTEXT,
					// где в pbCertEncoded находится декодированное значение сертификата. При таком подходе информация о сертификате корректно формирует класс X509Certificate2
					// однако использование X509Certificate2.Handle приведет к ошибке.
					if ((IntPtr)pCertContext.Target != IntPtr.Zero)
					{
						CERT_CONTEXT contextCert = Marshal.PtrToStructure<CERT_CONTEXT>((IntPtr)pCertContext.Target);
						byte[] ctx = new byte[contextCert.cbCertEncoded];
						Marshal.Copy(contextCert.pbCertEncoded, ctx, 0, ctx.Length);

						certFromSign = new X509Certificate2(ctx);
					}

					//TODO: закомментировал т.к под Linux не реализовано получение списка доверенных издателей
					//if (isCheckTrusted)
					//{
					//	log.LogDebug("Сертификат из подписи успешно получен. Проверяем наличие сертификата в списке доверенных издателей.");

					//	var trustedCerts = GetTrustedCertificates();

					//	if (trustedCerts.Count <= 0)
					//	{
					//		log.LogError("Список доверенных издателей пуст. Отсутствует доверие к сертификату.");
					//		return false;
					//	}

					//	if (!trustedCerts.Contains(certFromSign))
					//	{
					//		log.LogError("Сертификат указанный в подписи не найден среди доверенных издателей.");
					//		return false;
					//	}
					//}
				}
				catch (Exception ex)
				{
					log.LogError($"Необработанная ошибка при попытке проверить сертификат из подписи на наличие в списке доверенных. {ex.Message}.");
					return false;
				}
				finally
				{
					CApiExtUnix.CertFreeCertificateContext((IntPtr)pCertContext.Target);
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
				HashAlgorithm hash = new Gost2001Unix();
				hashResult = hash.ComputeHash(data);
			}
			else if (algId == CApiExtConst.GOST2012_256)
			{
				log.LogDebug($"Полученный алгоритм хэширования {algId} соответствует ГОСТ-2012-256");
				var hash = new Gost2012_256Unix();
				hashResult = hash.ComputeHash(data);
			}
			else if (algId == CApiExtConst.GOST2012_512)
			{
				log.LogDebug($"Полученный алгоритм хэширования {algId} соответствует ГОСТ-2012-512");
				var hash = new Gost2012_512Unix();
				hashResult = hash.ComputeHash(data);
			}
			else
			{
				log.LogDebug($"Полученный алгоритм хэширования {algId} не соответствует поддерживаемым ГОСТ алгоритмам. Используем криптопровайдер системы.");
				throw new CryptographicException($"Неизвестный алгоритм хэширования: {algId}.");
				// Ветка для использования MS провайдера при формировании хэш
				//HashAlgorithm hash = new HashMsApiUtil((int)algId);
				//hashResult = hash.ComputeHash(data);
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
		/// Метод получения алгоритма хэширования
		/// </summary>
		/// <param name="signatureAlgOid"></param>
		/// <returns></returns>
		internal static CRYPT_OID_INFO GetHashAlg(string signatureAlgOid)
		{
			IntPtr sigId = CApiExtUnix.CryptFindOIDInfo(OidKeyType.Oid, signatureAlgOid, OidGroup.SignatureAlgorithm);

			CRYPT_OID_INFO CertInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(sigId);

			uint alg = CertInfo.Algid;

			IntPtr int_addr = Marshal.AllocHGlobal(Marshal.SizeOf(alg));
			Marshal.WriteInt32(int_addr, (int)alg);

			IntPtr sigs = CApiExtUnix.CryptFindOIDInfo(OidKeyType.AlgorithmID, int_addr, OidGroup.SignatureAlgorithm);

			CRYPT_OID_INFO sigsInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(sigs);

			if (sigs == IntPtr.Zero)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			IntPtr hass = CApiExtUnix.CryptFindOIDInfo(OidKeyType.AlgorithmID, int_addr, OidGroup.HashAlgorithm);

			CRYPT_OID_INFO hassInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(hass);

			if (hass == IntPtr.Zero)
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return hassInfo;
		}

		/// <summary>
		/// Метод реализующий подписание данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="hCert"></param>
		/// <returns></returns>
		private byte[] Sign(byte[] data, IntPtr hCert)
		{
			log.LogDebug("Пытаемся выполнить метод подписи данных.");
			log.LogDebug("Заполняем структуру данных содержащую основные параметры необходимые для подписи.");

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

			log.LogDebug($"Пытаемся получить информацию о сертификате.");

			CApiExtConst.CERT_CONTEXT contextCert = Marshal.PtrToStructure<CApiExtConst.CERT_CONTEXT>(hCert);
			CApiExtConst.CERT_INFO certInfo = Marshal.PtrToStructure<CApiExtConst.CERT_INFO>(contextCert.pCertInfo);

			log.LogDebug("Информация о сертификате успешно получена.");
			log.LogDebug("Пытаемся получить информацию об алгоритме хэширования.");

			var signatureAlg = SignServiceUtils.GetSignatureAlg(certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId);
			var cryptOidInfo = GetHashAlg(signatureAlg);

			//Содержащий алгоритм хеширования, используемый для хеширования данных, подлежащих подписке.
			pParams.HashAlgorithm.pszObjId = cryptOidInfo.pszOID;


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

				log.LogDebug("Пытаемся получить размер для буфера содержащего массив байт подписи.");

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

				return signArray;
			}
			finally
			{
				Marshal.FreeHGlobal(rgpbToBeSigned);
				pGC.Free();
			}
		}
	}
}
