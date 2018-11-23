using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SignOVService.Model.Cryptography
{
	/// <summary>
	/// Класс обертка для работы с Крипто Api
	/// </summary>
	public class CryptoProvider
	{
		public CryptoProvider()
		{

		}

		/// <summary>
		/// Свойство определяет текущую ОС
		/// </summary>
		public static bool IsLinux
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
			var hCert = FindCertificate(thumbprint);
			return Sign(data, hCert);
		}

		/// <summary>
		/// Метод подписи данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="hCert"></param>
		/// <returns></returns>
		public byte[] Sign(byte [] data, IntPtr hCert)
		{
			//unsafe
			//{
				// Структура содержит информацию для подписания сообщений с использованием указанного контекста сертификата подписи
				CRYPT_SIGN_MESSAGE_PARA pParams = new CRYPT_SIGN_MESSAGE_PARA
				{
					// Размер этой структуры в байтах
					cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_SIGN_MESSAGE_PARA)),
					// Используемый тип кодирования
					dwMsgEncodingType = CryptoConst.PKCS_7_OR_X509_ASN_ENCODING,
					// Указатель на CERT_CONTEXT, который будет использоваться при подписании. 
					// Для того чтобы контекст предоставил доступ к закрытому сигнатурному ключу,
					// необходимо установить свойство CERT_KEY_PROV_INFO_PROP_ID или CERT_KEY_CONTEXT_PROP_ID
					pSigningCert = hCert,

					// Количество элементов в rgpMsgCert массиве CERT_CONTEXT структур.Если установлено ноль,
					// в подписанное сообщение не включаются сертификаты.
					cMsgCert = 1
				};

				CERT_CONTEXT contextCert = Marshal.PtrToStructure<CERT_CONTEXT>(hCert);
				CERT_INFO certInfo = Marshal.PtrToStructure<CERT_INFO>(contextCert.pCertInfo);

				//Содержащий алгоритм хеширования, используемый для хеширования данных, подлежащих подписке.
				pParams.HashAlgorithm.pszObjId = GetHashOidByKeyOid(certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId);

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
						// Подписываем данные
						// new uint[1] { (uint)data.Length } - Массив размеров в байтах буферов содержимого, на которые указывает rgpbToBeSigned
						if (!CApiLite.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
						{
							throw new CryptographicException("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
						}

						signArray = new byte[signArrayLength];

						if (!CApiLite.CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
						{
							throw new CryptographicException("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
						}
					}
					catch (Exception ex)
					{
						throw ex;
					}

					return signArray;
				}
				catch (Exception ex)
				{
					throw ex;
				}
				finally
				{
					// Освобождаем занимаемую память
					Marshal.FreeHGlobal(rgpbToBeSigned);
					pGC.Free();
				}
			//}
		}

		/// <summary>
		/// Метод подписи данных
		/// </summary>
		/// <param name="data"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		//public byte[] Sign(byte[] data, X509Certificate2Custom certificate)
		//{
		//	return Sign(data, certificate.CertHandle);
		//}

		/// <summary>
		/// Метод получения дескриптора сертификата
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		public IntPtr FindCertificate(string thumbprint)
		{
			//unsafe
			//{
				IntPtr handleSysStore = IntPtr.Zero;
				IntPtr handleCert = IntPtr.Zero;

				// Открываем хранилище сертификатов
				handleSysStore = CApiLite.CertOpenStore(
					CryptoConst.CERT_STORE_PROV_SYSTEM,
					0,
					IntPtr.Zero,
					65536, //CurrentUser
					"MY"
				);

				if (handleSysStore == IntPtr.Zero)
				{
					throw new CryptographicException("Ошибка при попытке получить дескриптор открытого хранилища сертификатов.");
				}

				// Получаем значение thumbprint в виде массива байт
				byte[] sha1Hash = HexStringToBinary(thumbprint);

				// Формируем параметр для метода поиска
				CRYPT_HASH_BLOB hashb = new CRYPT_HASH_BLOB();
				hashb.pbData = Marshal.AllocHGlobal(thumbprint.Length);
				Marshal.Copy(sha1Hash, 0, hashb.pbData, sha1Hash.Length);
				hashb.cbData = sha1Hash.Length;

				// Ищем сертификат в хранилище
				handleCert = CApiLite.CertFindCertificateInStore(
					handleSysStore,
					CryptoConst.PKCS_7_OR_X509_ASN_ENCODING, //Кодировка
					0,
					CryptoConst.CERT_FIND_SHA1_HASH, // ищем по отпечатку
					ref hashb, // значение отпечатка в байтах в памяти
					IntPtr.Zero
				);

				if (handleCert == IntPtr.Zero)
				{
					throw new CryptographicException("Ошибка при попытке получить дескриптор сертификата.");
				}

				var hCert = CApiLite.CertDuplicateCertificateContext(handleCert);
				FreeCertificateContext(handleCert);
				CApiLite.CertCloseStore(handleSysStore, 0);
				Marshal.FreeHGlobal(hashb.pbData);

				return hCert;
			//}
		}

		/// <summary>
		/// Метод поиска сертификата, возвращает сформированный объект X509Certificate2
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		//public X509Certificate2Custom FindX509Certificate2(string thumbprint)
		//{
		//	IntPtr hCert = this.FindCertificate(thumbprint);

		//	CERT_CONTEXT contextCert = Marshal.PtrToStructure<CERT_CONTEXT>(hCert);
		//	X509Certificate2Custom xCert = null;

		//	if (IsLinux)
		//	{
		//		byte[] ctx = new byte[contextCert.cbCertEncoded];
		//		Marshal.Copy(contextCert.pbCertEncoded, ctx, 0, ctx.Length);
		//		xCert = new X509Certificate2Custom(ctx, hCert);
		//	}
		//	else
		//	{
		//		xCert = new X509Certificate2Custom(hCert);
		//	}

		//	return xCert;
		//}

		/// <summary>
		/// Метод освобождения контекста сертификата
		/// </summary>
		/// <param name="hCert"></param>
		public void FreeCertificateContext(IntPtr hCert)
		{
			CApiLite.CertFreeCertificateContext(hCert);
		}

		/// <summary>
		/// Метод преобразования hex строки в массив байт (для преобразования значения thumbprint)
		/// </summary>
		/// <param name="hex"></param>
		/// <returns></returns>
		private byte[] HexStringToBinary(string hex)
		{
			byte[] bytes = new byte[hex.Length / 2];

			for (int i = 0; i < hex.Length; i += 2)
			{
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
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
			if (szKeyOid == CryptoConst.szOID_CP_GOST_R3410EL)
			{
				return CryptoConst.szOID_CP_GOST_R3411;
			}
			else if (szKeyOid == CryptoConst.szOID_CP_GOST_R3410_12_256)
			{
				return CryptoConst.szOID_CP_GOST_R3411_12_256;
			}
			else if (szKeyOid == CryptoConst.szOID_CP_GOST_R3410_12_512)
			{
				return CryptoConst.szOID_CP_GOST_R3411_12_512;
			}

			return null;
		}
	}
}
