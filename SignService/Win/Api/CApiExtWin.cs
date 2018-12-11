using SignService.Win.Handles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using static SignService.CApiExtConst;

namespace SignService.Win.Api
{
	internal class CApiExtWin
	{
		const string crypt32 = "crypt32.dll";
		const string advapi32 = "advapi32.dll";

		/// <summary>
		/// Функция подписи хэша
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="dwKeySpec"></param>
		/// <param name="sDescription"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pbSignature"></param>
		/// <param name="pdwSigLen"></param>
		/// <returns></returns>
		[DllImport(advapi32, BestFitMapping = false, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSignHash([In] SafeHashHandleCP hHash, [In] uint dwKeySpec, StringBuilder sDescription,
			[In] uint dwFlags, [In][Out] byte[] pbSignature, ref uint pdwSigLen);

		/// <summary>
		/// Функция CryptAcquireCertificatePrivateKey получает закрытый ключ для сертификата. 
		/// Эта функция используется для получения доступа к закрытому ключу пользователя, 
		/// когда сертификат пользователя доступен, но дескриптор контейнера ключа пользователя недоступен. 
		/// </summary>
		/// <param name="pCert"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pvReserved"></param>
		/// <param name="phCryptProv"></param>
		/// <param name="pdwKeySpec"></param>
		/// <param name="pfCallerFreeProv"></param>
		/// <returns></returns>
		[DllImport(crypt32, CharSet = CharSet.Auto, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptAcquireCertificatePrivateKey([In] IntPtr pCert, [In] uint dwFlags, [In] IntPtr pvReserved,
			[In, Out] ref IntPtr phCryptProv, [In, Out] ref uint pdwKeySpec, [In, Out] ref bool pfCallerFreeProv);

		/// <summary>
		/// Функция открывает хранилище сертификатов
		/// </summary>
		/// <param name="lpszStoreProvider"></param>
		/// <param name="dwMsgAndCertEncodingType"></param>
		/// <param name="hCryptProv"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pvPara"></param>
		/// <returns></returns>
		[DllImport(crypt32, SetLastError = true)]
		internal static extern IntPtr CertOpenStore(
			[In] uint lpszStoreProvider,
			[In] uint dwMsgAndCertEncodingType,
			[In] IntPtr hCryptProv,
			[In] uint dwFlags,
			[In, MarshalAs(UnmanagedType.LPStr)] string pvPara
		);

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
		[DllImport(crypt32, SetLastError = true)]
		internal static extern IntPtr CertFindCertificateInStore(
			[In] IntPtr hCertStore,
			[In] uint dwCertEncodingType,
			[In] uint dwFindFlags,
			[In] uint dwFindType,
			[In] ref CApiExtConst.CRYPT_HASH_BLOB pvFindPara,
			[In] IntPtr pPrevCertContext
		);

		/// <summary>
		/// Функция дублирует контекст сертификата
		/// </summary>
		/// <param name="pCertContext"></param>
		/// <returns></returns>
		[DllImport(crypt32, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertDuplicateCertificateContext([In] IntPtr pCertContext);

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
		[DllImport(crypt32, SetLastError = true)]
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
		/// 
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
		[DllImport(crypt32, SetLastError = true)]
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
		/// 
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSetHashParam([In] SafeHashHandleCP hHash, [In] uint dwParam, [In][Out] byte[] pbData, [In] uint dwFlags);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="dwCertEncodingType"></param>
		/// <param name="pbCertEncoded"></param>
		/// <param name="cbCertEncoded"></param>
		/// <returns></returns>
		[DllImport(crypt32, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern IntPtr CertCreateCertificateContext(
			int dwCertEncodingType,
			byte[] pbCertEncoded,
			int cbCertEncoded
		);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="pdwDataLen"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptGetHashParam([In] SafeHashHandleCP hHash, [In] uint dwParam, [In][Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="pbData"></param>
		/// <param name="dwDataLen"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptHashData([In] SafeHashHandleCP hHash, byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="pszContainer"></param>
		/// <param name="pszProvider"></param>
		/// <param name="dwProvType"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, BestFitMapping = false, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true, ThrowOnUnmappableChar = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptAcquireContext([In][Out] ref SafeProvHandleCP hProv, [In] string pszContainer, [In] string pszProvider, [In] uint dwProvType, [In] uint dwFlags);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pHashCtx"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptDestroyHash(IntPtr pHashCtx);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hCryptProv"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, EntryPoint = "CryptSetProvParam", ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSetProvParam2(IntPtr hCryptProv, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="pdwReserved"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, BestFitMapping = false, CharSet = CharSet.Ansi, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptContextAddRef([In] IntPtr hProv, [In] byte[] pdwReserved, [In] uint dwFlags);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="dwKeyType"></param>
		/// <param name="pvKey"></param>
		/// <param name="dwGroupId"></param>
		/// <returns></returns>
		[DllImport(crypt32, CharSet = CharSet.None, ExactSpelling = false)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, IntPtr pvKey, OidGroup dwGroupId);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="dwKeyType"></param>
		/// <param name="pvKey"></param>
		/// <param name="dwGroupId"></param>
		/// <returns></returns>
		[DllImport(crypt32, CharSet = CharSet.None, ExactSpelling = false)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, String pvKey, OidGroup dwGroupId);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="Algid"></param>
		/// <param name="hKey"></param>
		/// <param name="dwFlags"></param>
		/// <param name="phHash"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptCreateHash([In] SafeProvHandleCP hProv, [In] uint Algid, [In] SafeKeyHandleCP hKey, [In] uint dwFlags, [In][Out] ref SafeHashHandleCP phHash);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, SetLastError = true)]
		internal static extern bool CryptReleaseContext(
			IntPtr hProv,
			int dwFlags
		);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hCertStore"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(crypt32, SetLastError = true)]
		internal static extern IntPtr CertCloseStore(
			IntPtr hCertStore,
			int dwFlags
		);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hCryptMsg"></param>
		/// <returns></returns>
		[DllImport(crypt32, SetLastError = true)]
		internal static extern bool CryptMsgClose(
			IntPtr hCryptMsg
		);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pCertContext"></param>
		/// <returns></returns>
		[DllImport(crypt32, SetLastError = true)]
		internal static extern bool CertFreeCertificateContext(
			IntPtr pCertContext
		);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pKeyCtx"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptDestroyKey(IntPtr pKeyCtx);
	}
}
