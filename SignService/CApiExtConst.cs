using System;
using System.Runtime.InteropServices;

namespace SignService
{
	/// <summary>
	/// Класс обертка для используемых констант и структур данных
	/// </summary>
	internal class CApiExtConst
	{
		internal static uint PP_KEYEXCHANGE_PIN = 0x20;
		internal static uint PP_SIGNATURE_PIN = 0x21;

		internal static uint PP_VERIFYPASS_FLAG = 0x01;

		// CryptAcquireCertificatePrivateKey const
		internal static uint CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001;
		internal static uint CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002;

		internal static uint CRYPT_MESSAGE_SILENT_KEYSET_FLAG = CRYPT_ACQUIRE_SILENT_FLAG;
		internal static uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;
		internal static uint CRYPT_SILENT = 0x40;

		internal static uint CRYPT_VERIFYCONTEXT = 0xF0000000;

		internal static uint PP_NAME = 0x4;
		internal static uint PP_CONTAINER = 0x6;


		/// <summary>
		/// Параметры необходимые для метода формирования открепленной подписи
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_SIGN_MESSAGE_PARA
		{
			internal uint cbSize;
			internal uint dwMsgEncodingType;
			internal IntPtr pSigningCert;
			internal CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
			internal IntPtr pvHashAuxInfo;
			internal uint cMsgCert;
			internal IntPtr rgpMsgCert;
			internal uint cMsgCrl;
			internal IntPtr rgpMsgCrl;
			internal uint cAuthAttr;
			internal IntPtr rgAuthAttr;
			internal uint cUnauthAttr;
			internal IntPtr rgUnauthAttr;
			internal uint dwFlags;
			internal uint dwInnerContentType;
			internal IntPtr HashEncryptionAlgorithm;
			internal IntPtr pvHashEncryptionAuxInfo;
		}

		/// <summary>
		/// Структура используемая для формирования фильтра поиска сертификата
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_HASH_BLOB
		{
			public int cbData;
			public IntPtr pbData;
		}

		/// <summary>
		/// Структура необходимая для проверки валидности открепленной подписи
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_VERIFY_MESSAGE_PARA
		{
			public int cbSize;
			public uint dwMsgAndCertEncodingType;
			public int hCryptProv;
			public IntPtr pfnGetSignerCertificate;
			public IntPtr pvGetArg;
		}

		/// <summary>
		/// Константы для ГОСТ 2001
		/// </summary>
		internal static class Gost3411Consts
		{
			internal static readonly int HashAlgId = 32798;
			internal static readonly int HashSizeValue = 256;
			internal static readonly string HashGost3411AlgOid = "1.3.6.1.4.1.4929.2.20";
		}

		/// <summary>
		/// Константы для ГОСТ 2012-256
		/// </summary>
		internal static class Gost3411_12_256Consts
		{
			internal static readonly int HashAlgId = 32801;
			internal static readonly int HashSizeValue = 256;
		}

		/// <summary>
		/// Константы для ГОСТ 2012-512
		/// </summary>
		internal static class Gost3411_12_512Consts
		{
			internal static readonly int HashAlgId = 32802;
			internal static readonly int HashSizeValue = 512;
		}

		/// <summary>
		/// Значение алгоритмов хэширования для разных ГОСТ
		/// </summary>
		internal const int GOST341194 = 0x0000801e; // 32798
		internal const int GOST2012_256 = 0x00008021; // 32801
		internal const int GOST2012_512 = 0x00008022; // 32802

		/* CRYPT_HASH_ALG_OID_GROUP_ID */
		internal const string szOID_CP_GOST_R3411 = "1.2.643.2.2.9";
		internal const string szOID_CP_GOST_R3411_12_256 = "1.2.643.7.1.1.2.2";
		internal const string szOID_CP_GOST_R3411_12_512 = "1.2.643.7.1.1.2.3";

		/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
		internal const string szOID_CP_GOST_R3410 = "1.2.643.2.2.20";
		internal const string szOID_CP_GOST_R3410EL = "1.2.643.2.2.19";
		internal const string szOID_CP_GOST_R3410_12_256 = "1.2.643.7.1.1.1.1";
		internal const string szOID_CP_GOST_R3410_12_512 = "1.2.643.7.1.1.1.2";
		internal const string szOID_CP_DH_EX = "1.2.643.2.2.99";
		internal const string szOID_CP_DH_EL = "1.2.643.2.2.98";
		internal const string szOID_CP_DH_12_256 = "1.2.643.7.1.1.6.1";
		internal const string szOID_CP_DH_12_512 = "1.2.643.7.1.1.6.2";
		internal const string szOID_CP_GOST_R3410_94_ESDH = "1.2.643.2.2.97";
		internal const string szOID_CP_GOST_R3410_01_ESDH = "1.2.643.2.2.96";

		/* CRYPT_SIGN_ALG_OID_GROUP_ID */
		internal const string szOID_CP_GOST_R3411_R3410 = "1.2.643.2.2.4";
		internal const string szOID_CP_GOST_R3411_R3410EL = "1.2.643.2.2.3";
		internal const string szOID_CP_GOST_R3411_12_256_R3410 = "1.2.643.7.1.1.3.2";
		internal const string szOID_CP_GOST_R3411_12_512_R3410 = "1.2.643.7.1.1.3.3";

		/*sha1RSA*/
		internal const string szOID_CP_SHA1RSA_PUBLIC_KEY = "1.2.840.113549.1.1.1";
		internal const string szOID_CP_SHA1RSA_SIGN_ALG = "1.2.840.113549.1.1.5";

		//#define CERT_CLOSE_STORE_FORCE_FLAG         0x00000001
		internal const int CERT_CLOSE_STORE_FORCE_FLAG = 1;

		// cert encoding flags.
		internal const uint CRYPT_ASN_ENCODING = 0x00000001;
		internal const uint CRYPT_NDR_ENCODING = 0x00000002;
		internal const uint X509_ASN_ENCODING = 0x00000001;
		internal const uint X509_NDR_ENCODING = 0x00000002;
		internal const uint PKCS_7_ASN_ENCODING = 0x00010000;
		internal const uint PKCS_7_NDR_ENCODING = 0x00020000;
		internal const uint PKCS_7_OR_X509_ASN_ENCODING = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);

		internal const uint CERT_COMPARE_SHA1_HASH = 1;
		internal const uint CERT_COMPARE_SHIFT = 16;
		internal const uint CERT_FIND_SHA1_HASH = ((int)CERT_COMPARE_SHA1_HASH << (int)CERT_COMPARE_SHIFT);

		internal enum OidKeyType
		{
			Oid = 1,
			Name = 2,
			AlgorithmID = 3,
			SignatureID = 4,
			CngAlgorithmID = 5,
			CngSignatureID = 6
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_OID_INFO
		{
			internal uint cbSize;
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszOID;
			internal string pwszName;
			internal uint dwGroupId;
			internal uint Algid;
			internal CRYPTOAPI_BLOB ExtraInfo;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPTOAPI_BLOB
		{
			internal int cbData;
			internal IntPtr pbData;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CERT_PUBLIC_KEY_INFO
		{
			internal CRYPT_ALGORITHM_IDENTIFIER Algorithm;
			internal CRYPT_BIT_BLOB PublicKey;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct CERT_CONTEXT
		{
			internal uint dwCertEncodingType;
			internal IntPtr pbCertEncoded;
			internal uint cbCertEncoded;
			internal IntPtr pCertInfo;
			internal IntPtr hCertStore;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_BIT_BLOB
		{
			internal uint cbData;
			internal IntPtr pbData;
			internal uint cUnusedBits;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_ALGORITHM_IDENTIFIER
		{
			internal string pszObjId;
			internal CRYPT_OBJID_BLOB Parameters;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CRYPT_OBJID_BLOB
		{
			internal uint cbData;
			internal IntPtr pbData;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct CERT_INFO
		{
			internal uint dwVersion;
			internal CRYPTOAPI_BLOB SerialNumber;
			internal CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
			internal CRYPTOAPI_BLOB Issuer;
			internal System.Runtime.InteropServices.ComTypes.FILETIME NotBefore;
			internal System.Runtime.InteropServices.ComTypes.FILETIME NotAfter;
			internal CRYPTOAPI_BLOB Subject;
			internal CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
			internal CRYPT_BIT_BLOB IssuerUniqueId;
			internal CRYPT_BIT_BLOB SubjectUniqueId;
			internal uint cExtension;
			internal IntPtr rgExtension;
		}

		/// <summary>
		// Инициализирует хранилище с сертификатами, CRL и CTL из указанного системного хранилища.
		// Хранилище системы представляет собой логическое хранилище, состоящее из одного или нескольких 
		// физических хранилищ.
		// Физическое хранилище, связанное с системным хранилищем, 
		// регистрируется функцией CertRegisterPhysicalStore.
		// После открытия системного хранилища все физические хранилища,
		// связанные с ним, также открываются вызовами CertOpenStore и добавляются в коллекцию хранилища систем с помощью функции
		// CertAddStoreToCollection.
		// Установленный флаг dwFlags указывает на расположение хранилища системы, 
		// обычно устанавливаемое на CERT_SYSTEM_STORE_CURRENT_USER.
		// Некоторые местоположения хранилища системы могут быть открыты удаленно;
		// pvPara значение: В pvPara параметр указывает на нуль-терминатором ANSI строкукоторая содержит имя системного хранилища, 
		// такие как «My» или «Root».
		/// </summary>
		internal const uint CERT_STORE_PROV_SYSTEM_A = 9;
		internal const uint CERT_STORE_PROV_SYSTEM_W = 10;
		internal const uint CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_A;

		// Значение для хранилища сертификатов, указывает на хранилище текущего пользователя
		internal const int CURRENT_USER = 65536;

		internal const uint AT_KEYEXCHANGE = 1;
		internal const uint AT_SIGNATURE = 2;
	}
}
