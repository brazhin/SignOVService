using SignService.CommonUtils;
using SignService.Unix.Api;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using static SignService.CApiExtConst;

namespace SignService.Unix.Utils
{
	internal class UnixExtUtil
	{
		//private static long CRYPT_VERIFYCONTEXT = 0xF0000000;
		private static object internalSyncObject;

		private static IntPtr unsafeGost2001ProvHandle;
		private static IntPtr unsafeGost2012_256ProvHandle;
		private static IntPtr unsafeGost2012_512ProvHandle;

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
		/// Заполнение данными хэш объекта
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="data"></param>
		/// <param name="idStart"></param>
		/// <param name="cbSize"></param>
		[SecurityCritical]
		internal static void HashData(IntPtr hHash, byte[] data, int idStart, int cbSize)
		{
			try
			{
				byte[] temp = data;
				Array.Copy(data, idStart, temp, 0, cbSize);

				if (!CApiExtUnix.CryptHashData(hHash, temp, (uint)cbSize, 0))
				{
					throw new CryptographicException($"Ошибка при попытке заполнить хэш объект данными. Код ошибки: {CApiExtUnix.GetLastError()}.");
				}

				temp = null;
			}
			catch (Exception ex)
			{
				throw new Exception($"Ошибка при попытке заполнить хэш объект данными. {ex.Message}.");
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hHash"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static byte[] EndHash(IntPtr hHash)
		{
			uint num = 0;

			if (!CApiExtUnix.CryptGetHashParam(hHash, 2, null, ref num, 0))
			{
				throw new CryptographicException($"Ошибка при попытке вычислить размер буфера для данных, " +
					$"управляющих операциями объекта функции хэширования. Код ошибки: {CApiExtUnix.GetLastError()}."
				);
			}

			byte[] numArray = new byte[num];

			if (!CApiExtUnix.CryptGetHashParam(hHash, 2, numArray, ref num, 0))
			{
				throw new CryptographicException($"Ошибка при попытке получить данные, управляющие операциями объекта функции хэширования. Код ошибки: {CApiExtUnix.GetLastError()}.");
			}

			return numArray;
		}

		/// <summary>
		/// Метод поиска провайдера поддерживающего ГОСТ 3411-2001
		/// </summary>
		internal static IntPtr StaticGost2001ProvHandle
		{
			[SecurityCritical]
			get
			{
				if (unsafeGost2001ProvHandle == null || unsafeGost2001ProvHandle == IntPtr.Zero)
				{
					lock (InternalSyncObject)
					{
						if (unsafeGost2001ProvHandle == null || unsafeGost2001ProvHandle == IntPtr.Zero)
						{
							CspParameters cspParameter = SignServiceUtils.GetCspParameters(GostEnum.Gost2001);
							IntPtr unsafeProvHandleCP = AcquireProvHandle(cspParameter);
							Thread.MemoryBarrier();
							unsafeGost2001ProvHandle = unsafeProvHandleCP;
						}
					}
				}

				return unsafeGost2001ProvHandle;
			}
		}

		/// <summary>
		/// Метод поиска провайдера поддерживающего ГОСТ 3410-2012-256
		/// </summary>
		internal static IntPtr StaticGost2012_256ProvHandle
		{
			[SecurityCritical]
			get
			{
				if (unsafeGost2012_256ProvHandle == null || unsafeGost2012_256ProvHandle == IntPtr.Zero)
				{
					lock (InternalSyncObject)
					{
						if (unsafeGost2012_256ProvHandle == null || unsafeGost2012_256ProvHandle == IntPtr.Zero)
						{
							CspParameters cspParameter = SignServiceUtils.GetCspParameters(GostEnum.Gost2012_256);
							IntPtr unsafeProvHandleCP = AcquireProvHandle(cspParameter);
							Thread.MemoryBarrier();
							unsafeGost2012_256ProvHandle = unsafeProvHandleCP;
						}
					}
				}

				return unsafeGost2012_256ProvHandle;
			}
		}

		/// <summary>
		/// Метод поиска провайдера поддерживающего ГОСТ 3410-2012-512
		/// </summary>
		internal static IntPtr StaticGost2012_512ProvHandle
		{
			[SecurityCritical]
			get
			{
				if (unsafeGost2012_512ProvHandle == null || unsafeGost2012_512ProvHandle == IntPtr.Zero)
				{
					lock (InternalSyncObject)
					{
						if (unsafeGost2012_512ProvHandle == null || unsafeGost2012_512ProvHandle == IntPtr.Zero)
						{
							CspParameters cspParameter = SignServiceUtils.GetCspParameters(GostEnum.Gost2012_512);
							IntPtr unsafeProvHandleCP = AcquireProvHandle(cspParameter);
							Thread.MemoryBarrier();
							unsafeGost2012_512ProvHandle = unsafeProvHandleCP;
						}
					}
				}

				return unsafeGost2012_512ProvHandle;
			}
		}

		/// <summary>
		/// Метод создания дескриптора объекта функции хэширования
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="algid"></param>
		/// <param name="hHash"></param>
		[SecurityCritical]
		internal static void CreateHash(IntPtr hProv, int algid, ref IntPtr hHash)
		{
			if (!CApiExtUnix.CryptCreateHash(hProv, (uint)algid, IntPtr.Zero, (uint)0, ref hHash))
			{
				throw new CryptographicException($"Ошибка при создании дескриптора объекта функции хеширования. Код ошибки: {CApiExtUnix.GetLastError()}.");
			}
		}

		/// <summary>
		/// Метод получения дескриптора CSP
		/// </summary>
		/// <param name="parameters"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static IntPtr AcquireProvHandle(CspParameters parameters)
		{
			if (parameters == null)
			{
				parameters = new CspParameters(75);
			}

			IntPtr invalidHandle = IntPtr.Zero;
			AcquireCSP(parameters, ref invalidHandle);

			return invalidHandle;
		}

		/// <summary>
		/// Метод получения дескриптора CSP
		/// </summary>
		/// <param name="param"></param>
		/// <param name="hProv"></param>
		[SecurityCritical]
		internal static void AcquireCSP(CspParameters param, ref IntPtr hProv)
		{
			uint num = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;// uint.MaxValue; // CRYPT_DEFAULT_CONTAINER_OPTIONAL

			if ((param.Flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				num = num | 32;
			}

			if (!CApiExtUnix.CryptAcquireContext(ref hProv, param.KeyContainerName, param.ProviderName, (uint)param.ProviderType, num))
			{
				throw new CryptographicException($"Ошибка при попытке получить дескриптор критопровайдера. Код ошибки: {CApiExtUnix.GetLastError()}.");
			}
		}

		/// <summary>
		/// Метод подписи хэш
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="keyNumber"></param>
		/// <param name="rgbHash"></param>
		/// <param name="dwFlags"></param>
		/// <param name="algId"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static byte[] SignValue(IntPtr hProv, int keyNumber, byte[] rgbHash, int dwFlags, int algId)
		{
			IntPtr hashHandle = SetupHashAlgorithm(hProv, rgbHash, algId);

			if(hashHandle == IntPtr.Zero)
			{
				throw new Exception("Не удалось получить дескриптор хэш для подписи.");
			}

			try
			{
				byte[] signArray = null;
				uint signArraySize = 0;

				// Вычисляем размер буфера под подпись
				if (!CApiExtUnix.CryptSignHash(hashHandle, (uint)keyNumber, null, (uint)dwFlags, signArray, ref signArraySize))
				{
					throw new CryptographicException($"Не удалось вычислить размер буфера для подписи хэш. Код ошибки: {CApiExtUnix.GetLastError()}.");
				}

				signArray = new byte[signArraySize];

				// Получаем подпись
				if (!CApiExtUnix.CryptSignHash(hashHandle, (uint)keyNumber, null, (uint)dwFlags, signArray, ref signArraySize))
				{
					throw new CryptographicException($"Не удалось вычислить подпись хэш. Код ошибки: {CApiExtUnix.GetLastError()}.");
				}

				return signArray;
			}
			finally
			{
				SignServiceUtils.DestroyHashHandle(hashHandle);
			}
		}

		/// <summary>
		/// Метод получает хэш по заданному алгоритму
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

			if (!CApiExtUnix.CryptGetHashParam(invalidHandle, 2, null, ref num, 0))
			{
				throw new CryptographicException($"Ошибка при попытке получить данные, управляющие операциями объекта функции хеширования. Код ошибки: {CApiExtUnix.GetLastError()}.");
			}

			if ((ulong)((int)rgbHash.Length) != (ulong)num)
			{
				throw new CryptographicException($"Ошибка при получении хэш по заданному алгоритму. Код ошибки: {-2146893822}.");
			}

			if (!CApiExtUnix.CryptSetHashParam(invalidHandle, 2, rgbHash, 0))
			{
				throw new CryptographicException($"Ошибка при установке начального содержимого хэша и выборе особенных алгоритмов хеширования. " +
					$"Код ошибки: {CApiExtUnix.GetLastError()}."
				);
			}

			return invalidHandle;
		}

		/// <summary>
		/// Метод получения хэндлера криптопровайдера
		/// </summary>
		/// <param name="certHandle"></param>
		/// <param name="keySpec"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static IntPtr GetHandler(IntPtr certHandle, out uint keySpec, string password)
		{
			IntPtr phProv = IntPtr.Zero;

			keySpec = AT_SIGNATURE;
			bool isNeedCleenup = true;

			// Get CSP handle
			bool bResult = CApiExtUnix.CryptAcquireCertificatePrivateKey(
				certHandle,
				CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_CACHE_FLAG, // Флаг указывающий, что если указан неверный пароль, вместо повторного запроса, вернуть ошибку
				IntPtr.Zero,
				ref phProv,
				ref keySpec,
				ref isNeedCleenup
			);

			if (!bResult || phProv == IntPtr.Zero)
			{
				throw new Exception($"Ошибка при попытке получить дескриптор CSP. Код ошибки: {CApiExtUnix.GetLastError()}.");
			}

			string keyContainerPassword = string.IsNullOrEmpty(password) ? "" : password;

			// Вводим пароль
			if (!SignServiceUtils.EnterContainerPassword(phProv, keyContainerPassword))
			{
				throw new Exception($"Ошибка при попытке установить значение пароля для контейнера ключей. Код ошибки: {CApiExtUnix.GetLastError()}.");
			}

			return phProv;
		}

		/// <summary>
		/// Метод проверки открепленной подписи
		/// </summary>
		/// <param name="signatureData"></param>
		/// <param name="messageData"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static bool VerifySignDetachedMessage(byte[] signatureData, byte[] messageData)
		{
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

				return result;
			}
			catch (Exception ex)
			{
				throw new CryptographicException($"Ошибка при попытке выполнить проверку открепленной подписи. {ex.Message}.");
			}
			finally
			{
				pCertContext.Free();
			}
		}
	}
}
