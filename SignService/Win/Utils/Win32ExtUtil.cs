using SignService.CommonUtils;
using SignService.Win.Api;
using SignService.Win.Handles;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using static SignService.CApiExtConst;

namespace SignService.Win.Utils
{
	internal class Win32ExtUtil
	{
		private static long CRYPT_VERIFYCONTEXT = 0xF0000000;
		private static object internalSyncObject;

		private static SafeProvHandleCP safeGost2001ProvHandle;
		private static SafeProvHandleCP safeGost2012_256ProvHandle;
		private static SafeProvHandleCP safeGost2012_512ProvHandle;

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
		/// Завершающий метод формирования хэш
		/// </summary>
		/// <param name="hHash"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static byte[] EndHash(SafeHashHandleCP hHash)
		{
			uint num = 0;
			if (!CApiExtWin.CryptGetHashParam(hHash, 2, null, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			byte[] numArray = new byte[num];
			if (!CApiExtWin.CryptGetHashParam(hHash, 2, numArray, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return numArray;
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
			bool bResult = false;
			IntPtr phProv = IntPtr.Zero;

			keySpec = CApiExtConst.AT_SIGNATURE;
			bool isNeedCleenup = true;

			// Get CSP handle
			bResult = CApiExtWin.CryptAcquireCertificatePrivateKey(
				certHandle,
				CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_CACHE_FLAG, // Флаг указывающий, что если указан неверный пароль, вместо повторного запроса, вернуть ошибку
				IntPtr.Zero,
				ref phProv,
				ref keySpec,
				ref isNeedCleenup
				);

			if (!bResult)
			{
				throw new Exception($"Ошибка при попытке получить дескриптор CSP. {Marshal.GetLastWin32Error()}");
			}

			string keyContainerPassword = string.IsNullOrEmpty(password) ? "" : password;

			// Вводим пароль
			if (!SignServiceUtils.EnterContainerPassword(phProv, password))
			{
				throw new Exception($"Ошибка при попытке установить значение пароля для контейнера ключей.");
			}

			return phProv;
		}

		/// <summary>
		/// Заполнение данными хэш объекта
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="data"></param>
		/// <param name="idStart"></param>
		/// <param name="cbSize"></param>
		[SecurityCritical]
		internal static void HashData(SafeHashHandleCP hHash, byte[] data, int idStart, int cbSize)
		{
			try
			{
				byte[] temp = data;
				Array.Copy(data, idStart, temp, 0, cbSize);

				if (!CApiExtWin.CryptHashData(hHash, temp, (uint)cbSize, 0))
				{
					throw new CryptographicException(Marshal.GetLastWin32Error());
				}

				temp = null;
			}
			catch (Exception ex)
			{
				throw new Exception("Ошибка в методе HashData. " + ex.Message);
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
		internal static byte[] SignValue(IntPtr hProv, int keyNumber, byte[] rgbHash, int dwFlags, int algId)
		{
			using (var prov = new SafeProvHandleCP(hProv))
			{
				using (var safeHashHandleCP = SetupHashAlgorithm(prov, rgbHash, algId))
				{
					byte[] signArray = null;
					uint signArraySize = 0;

					if (!CApiExtWin.CryptSignHash(safeHashHandleCP, (uint)keyNumber, null, (uint)dwFlags, signArray, ref signArraySize))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}

					signArray = new byte[signArraySize];

					if (!CApiExtWin.CryptSignHash(safeHashHandleCP, (uint)keyNumber, null, (uint)dwFlags, signArray, ref signArraySize))
					{
						throw new CryptographicException(Marshal.GetLastWin32Error());
					}

					return signArray;
				}
			}
		}

		/// <summary>
		/// Метод поиска провайдера поддерживающего ГОСТ 3411-2001
		/// </summary>
		internal static SafeProvHandleCP StaticGost2001ProvHandle
		{
			[SecurityCritical]
			get
			{
				if (safeGost2001ProvHandle == null)
				{
					lock (InternalSyncObject)
					{
						if (safeGost2001ProvHandle == null)
						{
							CspParameters cspParameter = SignServiceUtils.GetCspParameters(GostEnum.Gost2001);
							SafeProvHandleCP safeProvHandleCP = AcquireProvHandle(cspParameter);
							Thread.MemoryBarrier();
							safeGost2001ProvHandle = safeProvHandleCP;
						}
					}
				}

				return safeGost2001ProvHandle;
			}
		}

		/// <summary>
		/// Метод поиска провайдера поддерживающего ГОСТ 3410-2012-256
		/// </summary>
		internal static SafeProvHandleCP StaticGost2012_256ProvHandle
		{
			[SecurityCritical]
			get
			{
				if (safeGost2012_256ProvHandle == null)
				{
					lock (InternalSyncObject)
					{
						if (safeGost2012_256ProvHandle == null)
						{
							CspParameters cspParameter = SignServiceUtils.GetCspParameters(GostEnum.Gost2012_256);
							SafeProvHandleCP safeProvHandleCP = AcquireProvHandle(cspParameter);
							Thread.MemoryBarrier();
							safeGost2012_256ProvHandle = safeProvHandleCP;
						}
					}
				}

				return safeGost2012_256ProvHandle;
			}
		}

		/// <summary>
		/// Метод поиска провайдера поддерживающего ГОСТ 3410-2012-512
		/// </summary>
		internal static SafeProvHandleCP StaticGost2012_512ProvHandle
		{
			[SecurityCritical]
			get
			{
				if (safeGost2012_512ProvHandle == null)
				{
					lock (InternalSyncObject)
					{
						if (safeGost2012_512ProvHandle == null)
						{
							CspParameters cspParameter = SignServiceUtils.GetCspParameters(GostEnum.Gost2012_512);
							SafeProvHandleCP safeProvHandleCP = AcquireProvHandle(cspParameter);
							Thread.MemoryBarrier();
							safeGost2012_512ProvHandle = safeProvHandleCP;
						}
					}
				}

				return safeGost2012_512ProvHandle;
			}
		}

		/// <summary>
		/// Метод создания хэш объекта
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="algid"></param>
		/// <param name="hHash"></param>
		[SecurityCritical]
		internal static void CreateHash(SafeProvHandleCP hProv, int algid, ref SafeHashHandleCP hHash)
		{
			if (!CApiExtWin.CryptCreateHash(hProv, (uint)algid, SafeKeyHandleCP.InvalidHandle, (uint)0, ref hHash))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		/// <summary>
		/// Метод получения криптопровайдера
		/// </summary>
		/// <param name="parameters"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static SafeProvHandleCP AcquireProvHandle(CspParameters parameters)
		{
			if (parameters == null)
			{
				parameters = new CspParameters(75);
			}

			SafeProvHandleCP invalidHandle = SafeProvHandleCP.InvalidHandle;
			AcquireCSP(parameters, ref invalidHandle);

			return invalidHandle;
		}

		/// <summary>
		/// Метод получения криптопровайдера
		/// </summary>
		/// <param name="param"></param>
		/// <param name="hProv"></param>
		[SecurityCritical]
		internal static void AcquireCSP(CspParameters param, ref SafeProvHandleCP hProv)
		{
			uint num = (uint)CRYPT_VERIFYCONTEXT;// uint.MaxValue; // CRYPT_DEFAULT_CONTAINER_OPTIONAL

			if ((param.Flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				num = num | 32;
			}

			if (!CApiExtWin.CryptAcquireContext(ref hProv, param.KeyContainerName, param.ProviderName, (uint)param.ProviderType, num))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
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
		private static SafeHashHandleCP SetupHashAlgorithm(SafeProvHandleCP prov, byte[] rgbHash, int algId)
		{
			SafeHashHandleCP invalidHandle = SafeHashHandleCP.InvalidHandle;

			CreateHash(prov, algId, ref invalidHandle);

			uint num = 0;

			if (!CApiExtWin.CryptGetHashParam(invalidHandle, 2, null, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			if ((ulong)((int)rgbHash.Length) != (ulong)num)
			{
				throw new CryptographicException(-2146893822);
			}

			if (!CApiExtWin.CryptSetHashParam(invalidHandle, 2, rgbHash, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return invalidHandle;
		}

		/// <summary>
		/// Метод проверки открепленной подписи
		/// </summary>
		/// <param name="signatureData"></param>
		/// <param name="messageData"></param>
		/// <returns></returns>
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
