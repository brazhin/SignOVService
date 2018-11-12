using System;
using System.Runtime.InteropServices;

namespace SignOVService.Model.Cryptography
{
	internal class CApiLite
	{
		const string LIBCAPI20 = "crypt32.dll"; //"libcapi20.so";

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
			[In] IntPtr lpszStoreProvider,
			[In] uint dwMsgAndCertEncodingType,
			[In] IntPtr hCryptProv,
			[In] uint dwFlags,
			[In] string pvPara
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
		[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertFindCertificateInStore(
			[In] IntPtr hCertStore,
			[In] uint dwCertEncodingType,
			[In] uint dwFindFlags,
			[In] uint dwFindType,
			[In] IntPtr pvFindPara,
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
	}
}
