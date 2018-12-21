using SignService.Unix;
using SignService.Unix.Api;
using SignService.Unix.Gost;
using SignService.Win;
using SignService.Win.Api;
using SignService.Win.Gost;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static SignService.CApiExtConst;

namespace SignService.CommonUtils
{
	public static class SignServiceUtils
	{
		// Типы провайдеров для ГОСТ 2001
		private static int provTypeVipNet2001 = 2;
		private static int provTypeCryptoPro2001 = 75;

		// Типы провайдеров для ГОСТ 2012
		private static int provTypeVipNet2012 = 77;
		private static int provTypeCryptoPro2012 = 80;

		/// <summary>
		/// Соответствие для алгоритмов хэширования плагина КриптоПро
		/// </summary>
		private static readonly Dictionary<uint, int> hashCodesForPlagin = new Dictionary<uint, int>
		{
			{0x00008001, 1},
			{0x00008002, 2},
			{0x00008003, 3},
			{0x00008004, 0},
			{0x0000800c, 4},
			{0x0000800d, 5},
			{0x0000800e, 6},
			{0x0000801e, 100},
			{0x00008021, 101},
			{0x00008022, 102}
		};

		/// <summary>
		/// Соответствие алгоритма публичного ключа алгоритму подписи
		/// </summary>
		private static readonly Dictionary<string, string> oid = new Dictionary<string, string>
		{
			{ CApiExtConst.szOID_CP_GOST_R3410, CApiExtConst.szOID_CP_GOST_R3411_R3410 },
			{ CApiExtConst.szOID_CP_GOST_R3410EL, CApiExtConst.szOID_CP_GOST_R3411_R3410EL },
			{ CApiExtConst.szOID_CP_GOST_R3410_12_256, CApiExtConst.szOID_CP_GOST_R3411_12_256_R3410 },
			{ CApiExtConst.szOID_CP_GOST_R3410_12_512, CApiExtConst.szOID_CP_GOST_R3411_12_512_R3410 },

			//SHA1RSA
			{ CApiExtConst.szOID_CP_SHA1RSA_PUBLIC_KEY, CApiExtConst.szOID_CP_SHA1RSA_SIGN_ALG }
		};

		/// <summary>
		/// Значения алгоритмов подписи для XML
		/// </summary>
		private static readonly Dictionary<int, string> signatureMethods = new Dictionary<int, string>
		{
			{ 32798, "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"}, //ГОСТ 2001
			{ 32801, "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"} //ГОСТ 2012
		};

		/// <summary>
		/// Значения алгоритмов подписи для XML
		/// </summary>
		private static readonly Dictionary<int, string> digestMethods = new Dictionary<int, string>
		{
			{ 32798, "http://www.w3.org/2001/04/xmldsig-more#gostr3411"}, //ГОСТ 2001
			{ 32801, "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"} //ГОСТ 2012
		};

		/// <summary>
		/// Свойство определяет тип платформы
		/// </summary>
		internal static bool IsUnix
		{
			get
			{
				int iPlatform = (int)Environment.OSVersion.Platform;
				return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
			}
		}

		/// <summary>
		/// Метод для получения параметров CSP
		/// </summary>
		/// <param name="isNewGost"></param>
		/// <returns></returns>
		internal static CspParameters GetCspParameters(bool isNewGost)
		{
			CspParameters cspParameter;

			if (SignServiceProvider.Csp == CspType.VipNet)
				cspParameter = (isNewGost) ? new CspParameters(provTypeVipNet2012) : new CspParameters(provTypeVipNet2001); // VipNet константы
			else if (SignServiceProvider.Csp == CspType.CryptoPro)
				cspParameter = (isNewGost) ? new CspParameters(provTypeCryptoPro2012) : new CspParameters(provTypeCryptoPro2001); // КриптоПро константы
			else
				throw new Exception($"Ошибка при попытке определить тип используемого криптопровайдера. " +
					$"Ожидаемые значения: 0 - для использования КриптоПро CSP или 1 - для использования VipNet CSP. Полученное значение: {SignServiceProvider.Csp}.");

			return cspParameter;
		}

		/// <summary>
		/// Метод получает экземпляр класса HashAlgorithm для каждой платформы с поддержкой гост указанного в сертификате
		/// </summary>
		/// <param name="certificate"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static HashAlgorithm GetHashAlgObject(IntPtr certificate, ref int algId)
		{
			var certContext = Marshal.PtrToStructure<CERT_CONTEXT>(certificate);
			var certInfo = Marshal.PtrToStructure<CERT_INFO>(certContext.pCertInfo);
			var publicKeyAlg = certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId;
			string signatureAlgOid = GetSignatureAlg(publicKeyAlg);

			if (IsUnix)
			{
				var algInfo = SignServiceUnix.GetHashAlg(signatureAlgOid);
				algId = (int)algInfo.Algid;

				if (algInfo.Algid == GOST341194)
				{
					return new Gost2001Unix();
				}
				else if(algInfo.Algid == GOST2012_256)
				{
					return new Gost2012_256Unix();
				}
				else
				{
					throw new Exception($"Ошибка при попытке определить функцию хэширования.");
				}
			}
			else
			{
				var algInfo = SignServiceWin.GetHashAlg(signatureAlgOid);
				algId = (int)algInfo.Algid;

				if (algInfo.Algid == GOST341194)
				{
					return new Gost2001();
				}
				else if (algInfo.Algid == GOST2012_256)
				{
					return new Gost2012_256();
				}
				else
				{
					throw new Exception($"Ошибка при попытке определить функцию хэширования.");
				}
			}
		}

		/// <summary>
		/// Метолучения алгоритма ГОСТ
		/// </summary>
		/// <param name="certHandle"></param>
		/// <returns></returns>
		[SecurityCritical]
		internal static int GetAlgId(IntPtr certHandle)
		{
			try
			{
				if(certHandle == IntPtr.Zero)
				{
					throw new Exception("Ошибка при попытке получить Handle сертификата.");
				}

				var certContext = Marshal.PtrToStructure<CERT_CONTEXT>(certHandle);
				var certInfo = Marshal.PtrToStructure<CERT_INFO>(certContext.pCertInfo);
				var publicKeyAlg = certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId;
				string signatureAlgOid = GetSignatureAlg(publicKeyAlg);

				CRYPT_OID_INFO oidInfo = new CRYPT_OID_INFO();

				if (IsUnix)
				{
					oidInfo = SignServiceUnix.GetHashAlg(signatureAlgOid);
				}
				else
				{
					oidInfo = SignServiceWin.GetHashAlg(signatureAlgOid);
				}

				return (int)oidInfo.Algid;
			}
			catch(Exception ex)
			{
				throw new CryptographicException($"Ошибка при получении хэш алгоритма ГОСТ. {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод преобразует хэндлер сертификата в объект X509Certificate2 под каждую платформу
		/// </summary>
		/// <param name="certHandle"></param>
		/// <returns></returns>
		[SecurityCritical]
		public static X509Certificate2 GetX509Certificate2(IntPtr certHandle)
		{
			try
			{
				if (IsUnix)
				{
					CERT_CONTEXT contextCert = Marshal.PtrToStructure<CERT_CONTEXT>(certHandle);
					byte[] ctx = new byte[contextCert.cbCertEncoded];
					Marshal.Copy(contextCert.pbCertEncoded, ctx, 0, ctx.Length);

					return new X509Certificate2(ctx);
				}
				else
				{
					return new X509Certificate2(certHandle);
				}
			}
			catch(Exception ex)
			{
				throw new Exception($"Ошибка при попытке преобразовать значение указателя на сертификат к объекту вида X509Certificate2. {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод освобождаем контекст сертификата
		/// </summary>
		/// <param name="certHandle"></param>
		[SecurityCritical]
		internal static void FreeHandleCertificate(IntPtr certHandle)
		{
			if (IsUnix)
				CApiExtUnix.CertFreeCertificateContext(certHandle);
			else
				CApiExtWin.CertFreeCertificateContext(certHandle);
		}

		/// <summary>
		/// Метод освобождает контекст сертификата
		/// </summary>
		/// <param name="provHandle"></param>
		[SecurityCritical]
		internal static void ReleaseProvHandle(IntPtr provHandle)
		{
			if (SignServiceUtils.IsUnix)
				CApiExtUnix.CryptReleaseContext(provHandle, 0);
			else
				CApiExtWin.CryptReleaseContext(provHandle, 0);
		}

		/// <summary>
		/// Метод получения константы для метода подписи в XML
		/// </summary>
		/// <param name="algId"></param>
		/// <returns></returns>
		internal static string GetSignatureMethod(int algId)
		{
			return signatureMethods[algId];
		}

		/// <summary>
		/// Метод получения константы для цифровго метода
		/// </summary>
		/// <param name="algId"></param>
		/// <returns></returns>
		internal static string GetDigestMethod(int algId)
		{
			return digestMethods[algId];
		}

		/// <summary>
		/// Метод получения значения алгоритма подписи по значению алгоритма публичного ключа
		/// </summary>
		/// <param name="publicKeyAlg"></param>
		/// <returns></returns>
		internal static string GetSignatureAlg(string publicKeyAlg)
		{
			if (!oid.ContainsKey(publicKeyAlg))
			{
				throw new NullReferenceException("Ошибка при попытке получить значение алгоритма подписи по алгоритму публичного ключа.");
			}

			return oid[publicKeyAlg];
		}

		/// <summary>
		/// Метод получения значения хэш кода для браузерного плагина
		/// </summary>
		/// <param name="hashCode"></param>
		/// <returns></returns>
		internal static int GetHashCodeForPlugin(uint hashCode)
		{
			return hashCodesForPlagin.ContainsKey(hashCode) ? hashCodesForPlagin[hashCode] : 0;
		}

		/// <summary>
		/// Метод преобразования массива байт в hex строку
		/// </summary>
		/// <param name="bytes"></param>
		/// <returns></returns>
		internal static string ConvertByteToHex(byte[] bytes)
		{
			StringBuilder sb = new StringBuilder();

			for (int i = 0; i < bytes.Length; i++)
			{
				sb.Append(bytes[i].ToString("X2"));
			}

			return sb.ToString().Replace("-", "").ToLower();
		}

		/// <summary>
		/// Метод преобразования hex строки в массив байт (для преобразования значения thumbprint)
		/// </summary>
		/// <param name="hex"></param>
		/// <returns></returns>
		internal static byte[] HexStringToBinary(string hex)
		{
			byte[] bytes = new byte[hex.Length / 2];

			for (int i = 0; i < hex.Length; i += 2)
			{
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}

			return bytes;
		}
	}
}
