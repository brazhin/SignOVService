using SignOVService.Model.Cryptography;
using SignOVService.Model.Smev.Sign.Gosts.Const;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SignOVService.Model.Smev.Sign
{
	public class ApiCspUtil
	{
		private static List<string> providersBlackList = new List<string>();
		private static Dictionary<string, List<uint>> providersAlgs = new Dictionary<string, List<uint>>();

		/// <summary>
		/// Получает название и тип криптопровайдера, который реализует конкретный алгоритм.
		/// </summary>
		/// <param name="algId"></param>
		/// <returns></returns>
		public static KeyValuePair<string, int> FindProviderByAlg(uint algId)
		{
			KeyValuePair<string, int> installedCSP = new KeyValuePair<string, int>();
			int cbName;
			int dwType;
			int dwIndex;
			StringBuilder pszName;
			dwIndex = 0;
			dwType = 0;
			cbName = 0;

			bool error = true;

			while (CApiLite.CryptEnumProviders(dwIndex, IntPtr.Zero, 0, ref dwType, null, ref cbName) && string.IsNullOrEmpty(installedCSP.Key))
			{
				pszName = new StringBuilder(cbName);

				if (CApiLite.CryptEnumProviders(dwIndex++, IntPtr.Zero, 0, ref dwType, pszName, ref cbName))
				{
					//logger.Debug("Криптопровайдер name: " + pszName.ToString() + " type: " + dwType.ToString());

					if (CheckProviderByAlg(pszName.ToString(), (uint)dwType, algId))
					{
						installedCSP = new KeyValuePair<string, int>(pszName.ToString(), dwType);
						error = false;
					}
					else
					{
						//logger.Debug("Криптопровайдер не подходит name: " + pszName.ToString() + " type: " + dwType.ToString());
					}
				}
			}

			if (error)
			{
				throw new Exception("Криптопровайдер не найден!");
			}

			return installedCSP;
		}

		/// <summary>
		/// Проверка на реализацию алгоритма криптопровайдером.
		/// </summary>
		/// <param name="provName"></param>
		/// <param name="provType"></param>
		/// <param name="algId"></param>
		/// <returns></returns>
		public static bool CheckProviderByAlg(string provName, uint provType, uint algId)
		{
			bool result = false;
			IntPtr hProv = IntPtr.Zero;
			byte[] bytes = new byte[1000];
			uint dataLen = 1000;

			try
			{
				if (providersBlackList.Contains(provName))
				{
					result = false;
				}
				else if (providersAlgs.ContainsKey(provName))
				{
					result = providersAlgs[provName].Contains(algId);
				}
				else
				{
					List<uint> algs = new List<uint>();
					providersAlgs.Add(provName, algs);
					PROV_ENUMALGS provAlg;

					if (CApiLite.CryptAcquireContext(ref hProv, null, provName, provType, unchecked(CryptoConst.CAC_CRYPT_VERIFYCONTEXT)))
					{
						try
						{
							dataLen = 0;
							bytes = null;
							bool defaultContainer = CApiLite.CryptGetProvParam(hProv, CryptoConst.CGPP_PP_ENUMALGS, bytes, ref dataLen, CryptoConst.CGPP_CRYPT_ZERO);

							if (defaultContainer)
							{
								bytes = new byte[dataLen];
								defaultContainer = CApiLite.CryptGetProvParam(hProv, CryptoConst.CGPP_PP_ENUMALGS, bytes, ref dataLen, CryptoConst.CGPP_CRYPT_ZERO);

								if (bytes == null)
								{
									bytes = new byte[dataLen];
								}
								else
								{
									IntPtr intPtr = Marshal.AllocHGlobal(bytes.Length);

									try
									{
										Marshal.Copy(bytes, 0, intPtr, bytes.Length);
										provAlg = Marshal.PtrToStructure<PROV_ENUMALGS>(intPtr);

										uint algIdInt = algId;

										algs.Add((uint)provAlg.aiAlgid);

										if (provAlg.aiAlgid == algIdInt)
										{
											result = CheckProvider(hProv);

											if (result == false)
											{
												providersBlackList.Add(provName);
											}
										}
									}
									finally
									{
										Marshal.FreeHGlobal(intPtr);
									}
								}
							}

							bool first = CApiLite.CryptGetProvParam(hProv, CryptoConst.CGPP_PP_ENUMALGS, bytes, ref dataLen, CryptoConst.CGPP_CRYPT_FIRST);

							if (first && result == false)
							{
								if (dataLen > 0)
								{
									bytes = new byte[dataLen];
								}

								first = CApiLite.CryptGetProvParam(hProv, CryptoConst.CGPP_PP_ENUMALGS, bytes, ref dataLen, CryptoConst.CGPP_CRYPT_FIRST);

								if (bytes == null)
								{
									bytes = new byte[dataLen];
								}
								else
								{
									IntPtr intPtr = Marshal.AllocHGlobal(bytes.Length);

									try
									{
										Marshal.Copy(bytes, 0, intPtr, bytes.Length);
										provAlg = Marshal.PtrToStructure<PROV_ENUMALGS>(intPtr);

										uint algIdInt = algId;

										algs.Add((uint)provAlg.aiAlgid);

										if (provAlg.aiAlgid == algIdInt)
										{
											result = CheckProvider(hProv);

											if (result == false)
											{
												providersBlackList.Add(provName);
											}
										}
									}
									finally
									{
										Marshal.FreeHGlobal(intPtr);
									}
								}

								while (CApiLite.CryptGetProvParam(hProv, CryptoConst.CGPP_PP_ENUMALGS, bytes, ref dataLen, CryptoConst.CGPP_CRYPT_NEXT) && result == false)
								{
									if (bytes != null)
									{
										IntPtr intPtr = Marshal.AllocHGlobal(bytes.Length);

										try
										{
											Marshal.Copy(bytes, 0, intPtr, bytes.Length);
											provAlg = Marshal.PtrToStructure<PROV_ENUMALGS>(intPtr);

											uint algIdInt = algId;

											algs.Add((uint)provAlg.aiAlgid);

											if (provAlg.aiAlgid == algIdInt)
											{
												result = CheckProvider(hProv);

												if (result == false)
												{
													providersBlackList.Add(provName);
												}
											}
										}
										finally
										{
											Marshal.FreeHGlobal(intPtr);
										}
									}

									bytes = new byte[dataLen];
								}
							}

							while (CApiLite.CryptGetProvParam(hProv, CryptoConst.CGPP_PP_ENUMALGS, bytes, ref dataLen, CryptoConst.CGPP_CRYPT_NEXT))
							{
								//Console.WriteLine("ERROR - CryptGetProvParam failed.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()));
								//logger.Debug("ERROR - CryptGetProvParam failed.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()));
							}
						}
						finally
						{
							CApiLite.CryptReleaseContext(hProv, 0);
							//hProv.Close();
							//hProv.Dispose();
						}

						//hProv.Dispose();
					}
					else
					{
						//Console.WriteLine("ERROR - CryptAcquireContext failed.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()).ToString());
						//logger.Debug("ERROR - CryptAcquireContext failed.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()).ToString());
					}
				}
			}
			catch
			{
				//Console.WriteLine("ERROR.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()).ToString());
				//logger.Debug("ERROR.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()).ToString());
			}

			return result;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hProv"></param>
		/// <returns></returns>
		private static bool CheckProvider(IntPtr hProv)
		{
			bool result = false;

			IntPtr invalidHandle = IntPtr.Zero;

			try
			{
				// Проверяем доступность провайдера для создания хэша.
				CryptoProvider.CreateHash(hProv, Gost2001Const.HashAlgId, ref invalidHandle);
				result = true;
				//logger.Debug("CreateHash pass");
			}
			catch
			{
				//Console.WriteLine("ERROR - CreateHash failed.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()).ToString());
				//logger.Debug("ERROR - CreateHash failed.\n" + Marshal.GetLastWin32Error().ToString() + new Win32Exception(Marshal.GetLastWin32Error()).ToString());
			}
			finally
			{
				CApiLite.CryptReleaseContext(invalidHandle, 0);
				//invalidHandle.Dispose();
			}

			return result;
		}
	}
}
