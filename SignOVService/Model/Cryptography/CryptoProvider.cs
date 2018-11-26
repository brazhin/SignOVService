using SignOVService.Model.Smev.Sign;
using SignOVService.Model.Smev.Sign.Gosts;
using SignOVService.Model.Smev.Sign.Gosts.Const;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace SignOVService.Model.Cryptography
{
	/// <summary>
	/// Класс обертка для работы с Крипто Api
	/// </summary>
	public class CryptoProvider
	{
		private static IntPtr safeGost2001ProvHandle;
		private static object internalSyncObject;

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

		private static object InternalSyncObject
		{
			[SecurityCritical]
			get
			{
				if (internalSyncObject == null)
				{
					object obj = new object();
					Interlocked.CompareExchange(ref internalSyncObject, obj, null);
				}

				return internalSyncObject;
			}
		}

		/// <summary>
		/// Метод получения Криптопровайдера для работы с ГОСТ-алгоритмами
		/// </summary>
		/// <returns></returns>
		internal static IntPtr TryGetGostProvider()
		{
			if (safeGost2001ProvHandle == null || safeGost2001ProvHandle == IntPtr.Zero)
			{
				lock (InternalSyncObject)
				{
					if (safeGost2001ProvHandle == null || safeGost2001ProvHandle == IntPtr.Zero)
					{
						IntPtr safeProvHandleCP = IntPtr.Zero;
						KeyValuePair<string, int> cspParam = ApiCspUtil.FindProviderByAlg((uint)Gost2001Const.HashAlgId);
						safeProvHandleCP = AcquireProvHandle(new CspParameters(cspParam.Value));
						safeGost2001ProvHandle = safeProvHandleCP;
					}
				}
			}

			return safeGost2001ProvHandle;
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
		}

		/// <summary>
		/// Метод поиска сертификата, возвращает сформированный объект X509Certificate2
		/// </summary>
		/// <param name="thumbprint"></param>
		/// <returns></returns>
		public X509Certificate2Custom FindX509Certificate2(string thumbprint)
		{
			IntPtr hCert = FindCertificate(thumbprint);

			CERT_CONTEXT contextCert = Marshal.PtrToStructure<CERT_CONTEXT>(hCert);
			X509Certificate2Custom xCert = null;

			if (IsLinux)
			{
				byte[] ctx = new byte[contextCert.cbCertEncoded];
				Marshal.Copy(contextCert.pbCertEncoded, ctx, 0, ctx.Length);
				//xCert = new X509Certificate2(ctx);
				xCert = new X509Certificate2Custom(ctx, hCert);
			}
			else
			{
				xCert = new X509Certificate2Custom(hCert);
				//xCert = new X509Certificate2(hCert);
			}

			return xCert;
		}

		/// <summary>
		/// Метод освобождения контекста сертификата
		/// </summary>
		/// <param name="hCert"></param>
		public void FreeCertificateContext(IntPtr hCert)
		{
			CApiLite.CertFreeCertificateContext(hCert);
		}

		[SecurityCritical]
		public static void CreateHash(IntPtr hProv, int algid, ref IntPtr hHash)
		{
			if (!CApiLite.CryptCreateHash(hProv, (uint)algid, IntPtr.Zero, (uint)0, ref hHash))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		[SecurityCritical]
		public static void HashData(IntPtr hHash, byte[] data, int idStart, int cbSize)
		{
			byte[] numPointer;
			byte[] numArray = data;//
			byte[] numArray1 = numArray;//

			if (numArray == null || (int)numArray1.Length == 0)
			{
				throw new ArgumentNullException("numArray");
			}

			if (cbSize == 0)
			{
				throw new ArgumentException("cbSize == 0", "cbSize");
			}

			if (hHash == null || hHash == IntPtr.Zero)
			{
				throw new ArgumentNullException("hHash");
			}

			if (!CApiLite.CryptHashData(hHash, data, (uint)cbSize, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			//if (numArray == null || (int)numArray1.Length == 0)
			//{
			//	numPointer = null;

			//	//TODO:
			//	if (!CApiLite.CryptHashData(hHash, numPointer + idStart, (uint)cbSize, 0))
			//	{
			//		throw new CryptographicException(Marshal.GetLastWin32Error());
			//	}
			//}
			//else
			//{
			//	fixed (byte* numPointer2 = numArray1)
			//	{

			//		if (!CApiLite.CryptHashData(hHash, numPointer2 + idStart, (uint)cbSize, 0))
			//		{
			//			throw new CryptographicException(Marshal.GetLastWin32Error());
			//		}
			//	}
			//}

			numPointer = null;
		}

		[SecurityCritical]
		internal static byte[] EndHash(IntPtr hHash)
		{
			uint num = 0;

			if (!CApiLite.CryptGetHashParam(hHash, 2, null, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			byte[] numArray = new byte[num];

			if (!CApiLite.CryptGetHashParam(hHash, 2, numArray, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return numArray;
		}

		[SecurityCritical]
		internal static IntPtr GetHandler(IntPtr certHandle, out uint keySpec)
		{
			bool bResult = false;
			IntPtr phProv = IntPtr.Zero;

			keySpec = CryptoConst.AT_SIGNATURE;
			bool isNeedCleenup = true;

			// Get CSP handle
			bResult = CApiLite.CryptAcquireCertificatePrivateKey(
				certHandle,
				0,
				IntPtr.Zero,
				ref phProv,
				ref keySpec,
				ref isNeedCleenup
				);

			if (!bResult)
			{
				throw new Exception("CryptAcquireContext error #" + Marshal.GetLastWin32Error().ToString());
			}

			return phProv;
		}

		[SecurityCritical]
		internal static int ObjToAlgId(object hashAlg, OidGroup oidGroup)
		{
			if (hashAlg == null)
			{
				throw new ArgumentNullException("hashAlg");
			}

			string oID = null;

			string str = hashAlg as string;

			if (str != null)
			{
				oID = CryptoConfig.MapNameToOID(str) ?? str;
			}
			else if (hashAlg is Gost3411XmlHash)
			{
				oID = Gost2001Const.HashGost3411AlgOid;
			}
			else if (hashAlg is HashAlgorithm)
			{
				oID = CryptoConfig.MapNameToOID(hashAlg.GetType().ToString());
			}
			else if (hashAlg is Type)
			{
				oID = CryptoConfig.MapNameToOID(hashAlg.ToString());
			}

			if (oID == null)
			{
				throw new ArgumentException("Argument_InvalidValue");
			}

			return GetAlgIdFromOid(oID, oidGroup);
		}

		[SecuritySafeCritical]
		internal static int GetAlgIdFromOid(string oid, OidGroup oidGroup)
		{
			int result = 0;

			if (string.Equals(oid, "2.16.840.1.101.3.4.2.1", StringComparison.Ordinal))
			{
				result = 32780;
			}
			if (string.Equals(oid, "2.16.840.1.101.3.4.2.2", StringComparison.Ordinal))
			{
				result = 32781;
			}
			if (string.Equals(oid, "2.16.840.1.101.3.4.2.3", StringComparison.Ordinal))
			{
				result = 32782;
			}
			if (string.Equals(oid, Gost2001Const.HashGost3411AlgOid, StringComparison.Ordinal))
			{
				result = Gost2001Const.HashAlgId;
			}
			else
			{
				result = (int)FindOidInfo(OidKeyType.Oid, oid, oidGroup).Algid;
			}

			return result;
		}

		[SecurityCritical]
		internal static byte[] SignValue(IntPtr hProv, int keyNumber, byte[] rgbHash, int dwFlags, int algId)
		{
			//TODO: release handle
			byte[] numArray;
			byte[] numArray1 = null;
			uint num = 0;

			IntPtr safeHashHandleCP = SetupHashAlgorithm(hProv, rgbHash, algId);

			if (!CApiLite.CryptSignHash(safeHashHandleCP, (uint)keyNumber, null, (uint)dwFlags, numArray1, ref num))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			numArray1 = new byte[num];

			if (!CApiLite.CryptSignHash(safeHashHandleCP, (uint)keyNumber, null, (uint)dwFlags, numArray1, ref num))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			numArray = numArray1;

			return numArray;
		}

		[SecurityCritical]
		internal static IntPtr AcquireProvHandle(CspParameters parameters)
		{
			if (parameters == null)
			{
				parameters = new CspParameters(CryptoConst.CSP_TYPE);
			}

			IntPtr invalidHandle = IntPtr.Zero;
			AcquireCSP(parameters, ref invalidHandle);

			return invalidHandle;
		}

		[SecurityCritical]
		internal static void AcquireCSP(CspParameters param, ref IntPtr hProv)
		{
			uint num = (uint)CryptoConst.CRYPT_VERIFYCONTEXT;// uint.MaxValue; // CRYPT_DEFAULT_CONTAINER_OPTIONAL

			if ((param.Flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				num = num | 32;
			}

			if (!CApiLite.CryptAcquireContext(ref hProv, param.KeyContainerName, param.ProviderName, (uint)param.ProviderType, num))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		[SecurityCritical]
		private static CryptOidInfo FindOidInfo(OidKeyType keyType, string key, OidGroup group)
		{
			CryptOidInfo structure;
			IntPtr zero = IntPtr.Zero;
			RuntimeHelpers.PrepareConstrainedRegions();

			try
			{
				zero = (keyType != OidKeyType.Oid ? Marshal.StringToCoTaskMemUni(key) : Marshal.StringToCoTaskMemAnsi(key));

				if (!CApiLite.OidGroupWillNotUseActiveDirectory(group))
				{
					int flag = (int)group;
					IntPtr intPtr = CApiLite.CryptFindOIDInfo((uint)keyType, zero, (uint)(flag | -2147483648));
					if (intPtr != IntPtr.Zero)
					{
						structure = Marshal.PtrToStructure<CryptOidInfo>(intPtr);
						return structure;
					}
				}

				IntPtr intPtr1 = CApiLite.CryptFindOIDInfo((uint)keyType, zero, (uint)group);

				if (intPtr1 != IntPtr.Zero)
				{
					structure = Marshal.PtrToStructure<CryptOidInfo>(intPtr1);
				}
				else if (group == 0 || !(CApiLite.CryptFindOIDInfo((uint)keyType, zero, 0) != IntPtr.Zero))
				{
					CryptOidInfo cRYPTOIDINFO = new CryptOidInfo();
					structure = cRYPTOIDINFO;
				}
				else
				{
					structure = Marshal.PtrToStructure<CryptOidInfo>(intPtr1);
				}
			}
			finally
			{
				if (zero != IntPtr.Zero)
				{
					Marshal.FreeCoTaskMem(zero);
				}
			}

			return structure;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prov"></param>
		/// <param name="rgbHash"></param>
		/// <param name="algId"></param>
		/// <returns></returns>
		[SecurityCritical]
		private static IntPtr SetupHashAlgorithm(IntPtr prov, byte[] rgbHash, int algId)
		{
			IntPtr invalidHandle = IntPtr.Zero;

			CreateHash(prov, algId, ref invalidHandle);

			uint num = 0;

			if (!CApiLite.CryptGetHashParam(invalidHandle, 2, null, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			if ((ulong)((int)rgbHash.Length) != (ulong)num)
			{
				throw new CryptographicException(-2146893822);
			}

			if (!CApiLite.CryptSetHashParam(invalidHandle, 2, rgbHash, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return invalidHandle;
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
