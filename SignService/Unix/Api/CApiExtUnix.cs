using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using static SignService.CApiExtConst;

namespace SignService.Unix.Api
{
	/// <summary>
	/// Класс для подключения функций API КриптоПро (capilite)
	/// </summary>
	internal class CApiExtUnix
	{
		const string libCapi20 = "/opt/cprocsp/lib/amd64/libcapi20.so";

		/// <summary>
		/// Функция получает первый или следующий сертификат в хранилище сертификатов.
		/// Эта функция используется в цикле для того, чтобы последовательно получить все сертификаты в хранилище сертификатов.
		/// </summary>
		/// <param name="hCertStore"></param>
		/// <param name="pPrevCertContext"></param>
		/// <returns></returns>
		[DllImport(libCapi20, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr CertEnumCertificatesInStore(
			[In] IntPtr hCertStore,
			[In] IntPtr pPrevCertContext
		);

		/// <summary>
		/// Функция CryptAcquireCertificatePrivateKey получает дескриптор HCRYPTPROV CSP , включая доступ к связанному с ним ключевому контейнеруи параметр dwKeySpec
		/// для определенного пользователем контекста сертификата.
		/// Эта функция используется для получения доступа к закрытому ключу пользователя, когда сертификат пользователя доступен,
		/// а дескриптор CSP с пользовательским ключевым контейнером не является доступным.
		/// Эту функцию может использовать только владелец закрытого ключа, а не любой пользователь.
		/// </summary>
		/// <param name="pCert"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pvReserved"></param>
		/// <param name="phCryptProv"></param>
		/// <param name="pdwKeySpec"></param>
		/// <param name="pfCallerFreeProv"></param>
		/// <returns></returns>
		[DllImport(libCapi20, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptAcquireCertificatePrivateKey([In] IntPtr pCert, [In] uint dwFlags, [In] IntPtr pvReserved,
			[In, Out] ref IntPtr phCryptProv, [In, Out] ref uint pdwKeySpec, [In, Out] ref bool pfCallerFreeProv);

		/// <summary>
		/// Функция CryptReleaseContext освобождает дескриптор CSP и ключевой контейнер.
		/// При каждом вызове этой функции счетчик ссылок на CSP уменьшается на единицу.
		/// Когда счетчик ссылок обнуляется, контекст полностью освобождается и более не может быть использован ни одной функцией данного приложения.
		/// Приложение вызывает эту функцию после завершения использования CSP.
		/// После вызова этой функции освобожденный дескриптор CSP становится более не действительным.
		/// Эта функция не уничтожает ключевые контейнеры и ключевые пары.
		/// </summary>
		/// <param name="hCryptProv"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(libCapi20, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags);

		/// <summary>
		/// Функция CryptSetHashParam переделывает операции объекта функции хеширования, включая установку начального содержимого хеша и выбор особенных алгоритмов хеширования.
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(libCapi20, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, [In] uint dwFlags);

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
		[DllImport(libCapi20, BestFitMapping = false, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptSignHash([In] IntPtr hHash, [In] uint dwKeySpec, StringBuilder sDescription,
			[In] uint dwFlags, [In][Out] byte[] pbSignature, ref uint pdwSigLen);

		/// <summary>
		/// Функция CryptCreateHash начинает хеширование потока данных. 
		/// Она создает и возвращает вызвавшему ее приложению дескриптор объекта функции хеширования CSP.
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="Algid"></param>
		/// <param name="hKey"></param>
		/// <param name="dwFlags"></param>
		/// <param name="phHash"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptCreateHash([In] IntPtr hProv, [In] uint Algid, [In] IntPtr hKey, [In] uint dwFlags, [In][Out] ref IntPtr phHash);

		/// <summary>
		/// Функция CryptAcquireContext используется для получения дескриптора к конкретному контейнеру ключей в конкретном поставщике криптографических услуг (CSP).
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="pszContainer"></param>
		/// <param name="pszProvider"></param>
		/// <param name="dwProvType"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(libCapi20, BestFitMapping = false, CharSet = CharSet.Auto, ExactSpelling = false, SetLastError = true, ThrowOnUnmappableChar = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptAcquireContext([In][Out] ref IntPtr hProv, [In] string pszContainer, [In] string pszProvider, [In] uint dwProvType, [In] uint dwFlags);

		/// <summary>
		/// Функция CryptGetHashParam получает данные, управляющие операциями объекта функции хеширования. 
		/// При использовании этой функции может быть получено действительное значение хеша.
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="pdwDataLen"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptGetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

		/// <summary>
		/// Функция CryptHashData добавляет данные в определенный объект функции хеширования. 
		/// Эта функция, а также функция CryptHashSessionKey могут быть вызваны несколько раз для вычисления хеша длинного или дискретного потока данных.
		/// Перед вызовом этой функции необходимо вызвать функцию CryptCreateHash для создания дескриптора объекта функции хеширования.
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="pbData"></param>
		/// <param name="dwDataLen"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptHashData([In] IntPtr hHash, byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags);

		/// <summary>
		/// Функция CryptDestroyHash уничтожает объект функции хеширования, ссылающийся на параметр hHash. 
		/// После того, как объект функции хеширования уничтожен, он не может больше использоваться.
		/// </summary>
		/// <param name="pHashCtx"></param>
		/// <returns></returns>
		[DllImport(libCapi20, CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SecurityCritical]
		[SuppressUnmanagedCodeSecurity]
		internal static extern bool CryptDestroyHash(IntPtr pHashCtx);

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
