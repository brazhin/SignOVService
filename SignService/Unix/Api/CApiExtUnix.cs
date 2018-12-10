using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using static SignService.CApiExtConst;

namespace SignService.Unix.Api
{
	internal class CApiExtUnix
	{
		const string libCapi20 = "/opt/cprocsp/lib/amd64/libcapi20.so";

		/// <summary>
		/// Функция проверки открепленной подписи
		/// </summary>
		/// <param name="pVerifyPara"></param>
		/// <param name="dwSignerIndex"></param>
		/// <param name="pbDetachedSignBlob"></param>
		/// <param name="cbDetachedSignBlob"></param>
		/// <param name="cToBeSigned"></param>
		/// <param name="rgpbToBeSigned"></param>
		/// <param name="rgcbToBeSigned"></param>
		/// <param name="ppSignerCert"></param>
		/// <returns></returns>
		[DllImport(libCapi20, SetLastError = true)]
		static internal extern bool CryptVerifyDetachedMessageSignature(
			ref CRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
			int dwSignerIndex,
			byte[] pbDetachedSignBlob,
			int cbDetachedSignBlob,
			int cToBeSigned,
			IntPtr[] rgpbToBeSigned,
			int[] rgcbToBeSigned,
			IntPtr ppSignerCert
		);

		/// <summary>
		/// Функция CryptFindOIDInfo получает первую предопределенную или зарегистрированную структуру CRYPT_OID_INFO, 
		/// согласованную с определенным типом ключа и с ключем. Поиск может быть ограничен идентификаторами объекта, 
		/// принадлежащими определенной группе идентификаторов объекта.
		/// </summary>
		/// <param name="dwKeyType"></param>
		/// <param name="pvKey"></param>
		/// <param name="dwGroupId"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.None, ExactSpelling = false)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, IntPtr pvKey, OidGroup dwGroupId);

		/// <summary>
		/// Функция CryptFindOIDInfo получает первую предопределенную или зарегистрированную структуру CRYPT_OID_INFO, 
		/// согласованную с определенным типом ключа и с ключем. Поиск может быть ограничен идентификаторами объекта, 
		/// принадлежащими определенной группе идентификаторов объекта.
		/// </summary>
		/// <param name="dwKeyType"></param>
		/// <param name="pvKey"></param>
		/// <param name="dwGroupId"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.None, ExactSpelling = false)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, String pvKey, OidGroup dwGroupId);

		/// <summary>
		/// Функция открывает хранилище сертификатов
		/// </summary>
		/// <param name="lpszStoreProvider"></param>
		/// <param name="dwMsgAndCertEncodingType"></param>
		/// <param name="hCryptProv"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pvPara"></param>
		/// <returns></returns>
		[DllImport(libCapi20, SetLastError = true)]
		internal static extern IntPtr CertOpenStore(
			[In] uint lpszStoreProvider,
			[In] uint dwMsgAndCertEncodingType,
			[In] IntPtr hCryptProv,
			[In] uint dwFlags,
			[In, MarshalAs(UnmanagedType.LPStr)] string pvPara
		);

		/// <summary>
		/// Функция закрывает хранилище сертификатов
		/// </summary>
		/// <param name="_hCertStore"></param>
		/// <param name="_iFlags"></param>
		/// <returns></returns>
		[DllImport(libCapi20, SetLastError = true)]
		internal static extern bool CertCloseStore(IntPtr _hCertStore, uint _iFlags);

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
		[DllImport(libCapi20, SetLastError = true)]
		internal static extern IntPtr CertFindCertificateInStore(
			[In] IntPtr hCertStore,
			[In] uint dwCertEncodingType,
			[In] uint dwFindFlags,
			[In] uint dwFindType,
			[In] ref CApiExtConst.CRYPT_HASH_BLOB pvFindPara,
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
		[DllImport(libCapi20, SetLastError = true)]
		internal static extern bool CryptSignMessage(
			[In] ref CApiExtConst.CRYPT_SIGN_MESSAGE_PARA pSignPara,
			[In] bool fDetachedSignature,
			[In] uint cToBeSigned,
			[In] IntPtr[] rgpbToBeSigned,
			[In] uint[] rgcbToBeSigned,
			byte[] pbSignedBlob,
			[In] ref uint pcbSignedBlob
		);

		/// <summary>
		/// Функция дублирует контекст сертификата
		/// </summary>
		/// <param name="pCertContext"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertDuplicateCertificateContext([In] IntPtr pCertContext);

		/// <summary>
		/// Функция освобождает контекст сертификата, уменьшая счетчик ссылок на единицу. 
		/// Когда счетчик ссылок обнуляется, функция освобождает память, выделенную под контекст сертификата.
		/// </summary>
		/// <param name="hPrev"></param>
		[DllImport(libCapi20, SetLastError = true)]
		internal static extern void CertFreeCertificateContext(IntPtr hPrev);
	}
}
