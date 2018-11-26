using SignOVService.Model.Smev.Sign;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace SignOVService.Model.Cryptography
{
	public class CApiLite
	{
		const string LIBCAPI20 = "/opt/cprocsp/lib/amd64/libcapi20.so";

		const string advapi32 = /*LIBCAPI20;*/"advapi32.dll";
		const string crypt32 =/* LIBCAPI20;*/"crypt32.dll";

		/// <summary>
		/// 
		/// </summary>
		/// <param name="group"></param>
		/// <returns></returns>
		internal static bool OidGroupWillNotUseActiveDirectory(OidGroup group)
		{
			if (group == OidGroup.HashAlgorithm || group == OidGroup.EncryptionAlgorithm || 
				group == OidGroup.PublicKeyAlgorithm || 
				group == OidGroup.SignatureAlgorithm || 
				group == OidGroup.Attribute || 
				group == OidGroup.ExtensionOrAttribute
			)
			{
				return true;
			}

			return group == OidGroup.KeyDerivationFunction;
		}

		/// <summary>
		/// Функция закрывает хранилище сертификатов
		/// </summary>
		/// <param name="_hCertStore"></param>
		/// <param name="_iFlags"></param>
		/// <returns></returns>
		[DllImport(crypt32, SetLastError = true)]
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
		[DllImport(crypt32, SetLastError = true)]
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
		[DllImport(crypt32, SetLastError = true)]
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
		[DllImport(crypt32, SetLastError = true)]
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
		[DllImport(crypt32, SetLastError = true)]
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

		[DllImport(crypt32, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true)]
		internal static extern IntPtr CertDuplicateCertificateContext([In] IntPtr pCertContext);

		/// <summary>
		/// Функция добавляет данные в определенный объект функции хеширования.
		/// Эта функция, а также функция CryptHashSessionKey могут быть вызваны несколько раз для вычисления хеша длинного или дискретного потока данных.
		/// Перед вызовом этой функции необходимо вызвать функцию CryptCreateHash для создания дескриптора объекта функции хеширования.
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="pbData"></param>
		/// <param name="dwDataLen"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptHashData([In] IntPtr hHash, byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags);

		/// <summary>
		/// Функция начинает хеширование потока данных. Она создает и возвращает вызвавшему ее приложению дескриптор объекта функции хеширования CSP.
		/// Этот дескриптор используется при дальнейших вызовах функций CryptHashData и CryptHashSessionKey при работе с сессионными ключами 
		/// и другими потоками данных.
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
		internal static extern bool CryptCreateHash([In] IntPtr hProv, [In] uint Algid, [In] IntPtr hKey, [In] uint dwFlags, [In][Out] ref IntPtr phHash);

		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptGetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

		[DllImport(crypt32, CharSet = CharSet.Auto, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptAcquireCertificatePrivateKey([In] IntPtr pCert, [In] uint dwFlags, [In] IntPtr pvReserved, 
			[In, Out] ref IntPtr phCryptProv, [In, Out] ref uint pdwKeySpec, [In, Out] ref bool pfCallerFreeProv);


		[DllImport(crypt32, CharSet = CharSet.Auto, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr CryptFindOIDInfo([In] uint dwKeyType, [In] IntPtr pvKey, [In] uint dwGroupId);

		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, [In] uint dwFlags);

		[DllImport(advapi32, BestFitMapping = false, CharSet = CharSet.Ansi, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSignHash([In] IntPtr hHash, [In] uint dwKeySpec, StringBuilder sDescription, 
			[In] uint dwFlags, [In][Out] byte[] pbSignature, ref uint pdwSigLen);

		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptDestroyHash(IntPtr pHashCtx);

		[DllImport(advapi32, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags);

		[DllImport(advapi32, BestFitMapping = false, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true, ThrowOnUnmappableChar = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptAcquireContext([In][Out] ref IntPtr hProv, 
			[In] string pszContainer, [In] string pszProvider, [In] uint dwProvType, [In] uint dwFlags);

		[DllImport(advapi32, CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptEnumProviders(
			int dwIndex,
			IntPtr pdwReserved,
			int dwFlags,
			ref int pdwProvType,
			StringBuilder pszProvName,
			ref int pcbProvName
		);

		[DllImport(advapi32, CharSet = CharSet.Unicode, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptGetProvParam([In] IntPtr hProv, [In] uint dwParam, [In][Out] byte[] pbData, ref uint dwDataLen, [In] uint dwFlags);

		[DllImport(crypt32, CharSet = CharSet.None, ExactSpelling = false)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		private static extern IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, IntPtr pvKey, OidGroup dwGroupId);

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
