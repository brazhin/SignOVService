using System;
using System.Runtime.InteropServices;

namespace SignOVService.Model.Cryptography
{
	public class CApiLite
	{
		const string LIBCAPI20 = "/opt/cprocsp/lib/amd64/libcapi20.so"; /*"crypt32.dll";*/

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

		//[DllImport(LIBCAPI20, SetLastError = true)]
		//internal static extern IntPtr CertEnumCertificatesInStore(
		//	IntPtr hCertStore,
		//	IntPtr pPrevCertContext
		//);

		[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertDuplicateCertificateContext([In] IntPtr pCertContext);

		//[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		//internal static extern bool CertSetCertificateContextProperty(
		//	CERT_CONTEXT pCertContext,
		//	uint dwPropId,
		//	uint dwFlags,
		//	IntPtr pvData
		//);

		//[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		//internal static extern uint CertEnumCertificateContextProperties(
		//	CERT_CONTEXT pCertContext,
		//	uint dwPropId
		//);

		//[DllImport(LIBCAPI20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		//internal static extern IntPtr CertOpenSystemStoreA(
		//	[In] uint hProv,
		//	[In] string pszSubsystemProtocol
		//);
	}
}
