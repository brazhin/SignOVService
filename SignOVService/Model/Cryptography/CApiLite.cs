using System;
using System.Runtime.InteropServices;

namespace SignOVService.Model.Cryptography
{
	public class CApiLite
	{
		const string LIBCAPI20 = "/opt/cprocsp/lib/amd64/libcapi20.so"; /*"crypt32.dll";*/

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

		internal struct CRYPT_ALGORITHM_IDENTIFIER
		{
			internal string pszObjId;
			internal CRYPT_OBJID_BLOB Parameters;
		}

		internal struct CRYPT_OBJID_BLOB
		{
			internal uint cbData;
			internal IntPtr pbData;
		}

		public struct CERT_CONTEXT
		{
			internal uint dwCertEncodingType;
			internal IntPtr pbCertEncoded;
			internal uint cbCertEncoded;
			internal IntPtr pCertInfo;
			internal IntPtr hCertStore;
		}

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

		internal struct CERT_PUBLIC_KEY_INFO
		{
			internal CRYPT_ALGORITHM_IDENTIFIER Algorithm;
			internal CRYPT_BIT_BLOB PublicKey;
		}

		internal struct CRYPT_BIT_BLOB
		{
			internal uint cbData;
			internal IntPtr pbData;
			internal uint cUnusedBits;
		}

		internal struct CRYPT_KEY_PROV_INFO
		{
			IntPtr pwszContainerName;
			IntPtr pwszProvName;
			uint dwProvType;
			uint dwFlags;
			uint cProvParam;
			CRYPT_KEY_PROV_PARAM rgProvParam;
			uint dwKeySpec;
		};

		internal struct CRYPT_KEY_PROV_PARAM
		{
			uint dwParam;
			IntPtr pbData;
			uint cbData;
			uint dwFlags;
		};

		[StructLayout(LayoutKind.Sequential)]
		public struct CRYPT_HASH_BLOB
		{
			public int cbData;
			public IntPtr pbData;
		}

		/// <summary>
		/// Функция закрывает хранилище сертификатов
		/// </summary>
		/// <param name="_hCertStore"></param>
		/// <param name="_iFlags"></param>
		/// <returns></returns>
		[DllImport(LIBCAPI20, SetLastError = true)]
		internal static extern bool CertCloseStore(IntPtr _hCertStore, uint _iFlags);

		/// <summary>
		/// Функция открывает хранилище сертификатов
		/// </summary>
		/// <param name="lpszStoreProvider"></param>
		/// <param name="dwMsgAndCertEncodingType"></param>
		/// <param name="hCryptProv"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pvPara"></param>
		/// <returns></returns>
		[DllImport(LIBCAPI20, SetLastError = true)]
		internal static extern IntPtr CertOpenStore(
			[In] uint lpszStoreProvider,
			[In] uint dwMsgAndCertEncodingType,
			[In] IntPtr hCryptProv,
			[In] uint dwFlags,
			[In, MarshalAs(UnmanagedType.LPStr)] string pvPara
		);

		/// <summary>
		/// Функция освобождает контекст сертификата, уменьшая счетчик ссылок на единицу. 
		/// Когда счетчик ссылок обнуляется, функция освобождает память, выделенную под контекст сертификата.
		/// </summary>
		/// <param name="hPrev"></param>
		[DllImport(LIBCAPI20, SetLastError = true)]
		internal static extern void CertFreeCertificateContext(IntPtr hPrev);

		/// <summary>
		/// Функция поиска сертификата в хранилище
		/// </summary>
		/// <param name="hCertStore"></param>
		/// <param name="dwCertEncodingType"></param>
		/// <param name="dwFindFlags"></param>
		/// <param name="dwFindType"></param>
		/// <param name="pvFindPara"></param>
		/// <param name="pPrevCertContext"></param>
		/// <returns></returns>
		[DllImport(LIBCAPI20, SetLastError = true)]
		internal static extern IntPtr CertFindCertificateInStore(
			[In] IntPtr hCertStore,
			[In] uint dwCertEncodingType,
			[In] uint dwFindFlags,
			[In] uint dwFindType,
			[In] ref CRYPT_HASH_BLOB pvFindPara,
			[In] IntPtr pPrevCertContext
		);

		/// <summary>
		/// Функция создает хеш определенного содержания, подписывает хеш и затем 
		/// производит закодирование и текста исходного сообщения, и подписанного хеша.
		/// </summary>
		/// <param name="pSignPara"></param>
		/// <param name="fDetachedSignature"></param>
		/// <param name="cToBeSigned"></param>
		/// <param name="rgpbToBeSigned"></param>
		/// <param name="rgcbToBeSigned"></param>
		/// <param name="pbSignedBlob"></param>
		/// <param name="pcbSignedBlob"></param>
		/// <returns></returns>
		[DllImport(LIBCAPI20, SetLastError = true)]
		internal static extern bool CryptSignMessage(
			[In] ref CRYPT_SIGN_MESSAGE_PARA pSignPara,
			[In] bool fDetachedSignature,
			[In] uint cToBeSigned,
			[In] IntPtr[] rgpbToBeSigned,
			[In] uint[] rgcbToBeSigned,
			byte[] pbSignedBlob,
			[In] ref uint pcbSignedBlob
		);

		[DllImport(LIBCAPI20, SetLastError = true)]
		internal static extern IntPtr CertEnumCertificatesInStore(
			IntPtr hCertStore,
			IntPtr pPrevCertContext
		);

		[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertDuplicateCertificateContext([In] IntPtr pCertContext);

		[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern bool CertSetCertificateContextProperty(
			CERT_CONTEXT pCertContext,
			uint dwPropId,
			uint dwFlags,
			IntPtr pvData
		);

		[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern uint CertEnumCertificateContextProperties(
			CERT_CONTEXT pCertContext,
			uint dwPropId
		);

		[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertOpenSystemStoreA(
			[In] uint hProv,
			[In] string pszSubsystemProtocol
		);
	}
}
