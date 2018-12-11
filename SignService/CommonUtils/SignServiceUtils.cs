using SignService.Unix;
using SignService.Unix.Gost;
using SignService.Win;
using SignService.Win.Gost;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static SignService.CApiExtConst;

namespace SignService.CommonUtils
{
	internal static class SignServiceUtils
	{
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
		/// Метод получает экземпляр класса HashAlgorithm для каждой платформы с поддержкой гост указанного в сертификате
		/// </summary>
		/// <param name="certificate"></param>
		/// <returns></returns>
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
		/// Метод преобразует хэндлер сертификата в объект X509Certificate2 под каждую платформу
		/// </summary>
		/// <param name="certHandle"></param>
		/// <returns></returns>
		internal static X509Certificate2 GetX509Certificate2(IntPtr certHandle)
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
		/// Метод получения хэш алгоритма по алгоритму публичного ключа //TODO: delete
		/// </summary>
		/// <param name="szKeyOid"></param>
		/// <returns></returns>
		internal static string GetHashOidByKeyOid(string szKeyOid)
		{
			if (szKeyOid == CApiExtConst.szOID_CP_GOST_R3410EL)
			{
				return CApiExtConst.szOID_CP_GOST_R3411;
			}
			else if (szKeyOid == CApiExtConst.szOID_CP_GOST_R3410_12_256)
			{
				return CApiExtConst.szOID_CP_GOST_R3411_12_256;
			}
			else if (szKeyOid == CApiExtConst.szOID_CP_GOST_R3410_12_512)
			{
				return CApiExtConst.szOID_CP_GOST_R3411_12_512;
			}

			return null;
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
