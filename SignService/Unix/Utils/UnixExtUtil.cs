using SignService.Unix.Api;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;

namespace SignService.Unix.Utils
{
	internal class UnixExtUtil
	{
		private static long CRYPT_VERIFYCONTEXT = 0xF0000000;
		private static object internalSyncObject;

		private static IntPtr unsafeGost2001ProvHandle;
		private static IntPtr unsafeGost2012_256ProvHandle;
		private static IntPtr unsafeGost2012_512ProvHandle;
		private static IntPtr unsafeMsProvHandle;

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
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			byte[] numArray = new byte[num];
			if (!CApiExtUnix.CryptGetHashParam(hHash, 2, numArray, ref num, 0))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}

			return numArray;
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
							IntPtr unsafeProvHandleCP = AcquireProvHandle(new CspParameters(80));
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
							IntPtr unsafeProvHandleCP = AcquireProvHandle(new CspParameters(81));
							Thread.MemoryBarrier();
							unsafeGost2012_512ProvHandle = unsafeProvHandleCP;
						}
					}
				}

				return unsafeGost2012_512ProvHandle;
			}
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
							IntPtr unsafeProvHandleCP = AcquireProvHandle(new CspParameters(75));
							Thread.MemoryBarrier();
							unsafeGost2001ProvHandle = unsafeProvHandleCP;
						}
					}
				}

				return unsafeGost2001ProvHandle;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="algid"></param>
		/// <param name="hHash"></param>
		[SecurityCritical]
		internal static void CreateHash(IntPtr hProv, int algid, ref IntPtr hHash)
		{
			if (!CApiExtUnix.CryptCreateHash(hProv, (uint)algid, IntPtr.Zero, (uint)0, ref hHash))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}

		/// <summary>
		/// 
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
		/// 
		/// </summary>
		/// <param name="param"></param>
		/// <param name="hProv"></param>
		[SecurityCritical]
		internal static void AcquireCSP(CspParameters param, ref IntPtr hProv)
		{
			uint num = (uint)CRYPT_VERIFYCONTEXT;// uint.MaxValue; // CRYPT_DEFAULT_CONTAINER_OPTIONAL

			if ((param.Flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				num = num | 32;
			}

			if (!CApiExtUnix.CryptAcquireContext(ref hProv, param.KeyContainerName, param.ProviderName, (uint)param.ProviderType, num))
			{
				throw new CryptographicException(Marshal.GetLastWin32Error());
			}
		}
	}
}
