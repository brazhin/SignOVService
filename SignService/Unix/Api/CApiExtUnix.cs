using System;
using System.Security.Cryptography;
using System.Text;
using static SignService.CApiExtConst;

namespace SignService.Unix.Api
{
	/// <summary>
	/// Класс для подключения функций API
	/// </summary>
	internal class CApiExtUnix
	{
		internal static bool CryptGetProvParam(IntPtr prov, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptGetProvParam(prov, dwParam, pbData, ref pdwDataLen, dwFlags);
			//else if (SignServiceProvider.Csp == CspType.VipNet)
			//	return CApiExtUnixVipNet.CryptSetProvParam(prov, dwParam, pbData, dwFlags);
			else
				throw new Exception($"CryptGetProvParam. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция установки параметров криптопровайдера
		/// </summary>
		/// <param name="prov"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		internal static bool CryptSetProvParam(IntPtr prov, uint dwParam, byte[] pbData, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptSetProvParam(prov, dwParam, pbData, dwFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptSetProvParam(prov, dwParam, pbData, dwFlags);
			else
				throw new Exception($"CryptSetProvParam. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция получает первый или следующий сертификат в хранилище сертификатов.
		/// Эта функция используется в цикле для того, чтобы последовательно получить все сертификаты в хранилище сертификатов.
		/// </summary>
		/// <param name="hCertStore"></param>
		/// <param name="pPrevCertContext"></param>
		/// <returns></returns>
		internal static IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
			else
				throw new Exception($"CertEnumCertificatesInStore. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptAcquireCertificatePrivateKey(IntPtr pCert, uint dwFlags, IntPtr pvReserved, ref IntPtr phCryptProv, 
			ref uint pdwKeySpec, ref bool pfCallerFreeProv)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvReserved, ref phCryptProv, ref pdwKeySpec, ref pfCallerFreeProv);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvReserved, ref phCryptProv, ref pdwKeySpec, ref pfCallerFreeProv);
			else
				throw new Exception($"CryptAcquireCertificatePrivateKey. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptReleaseContext(hCryptProv, dwFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptReleaseContext(hCryptProv, dwFlags);
			else
				throw new Exception($"CryptReleaseContext. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция CryptSetHashParam переделывает операции объекта функции хеширования, включая установку начального содержимого хеша и выбор особенных алгоритмов хеширования.
		/// </summary>
		/// <param name="hHash"></param>
		/// <param name="dwParam"></param>
		/// <param name="pbData"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		internal static bool CryptSetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
			else
				throw new Exception($"CryptSetHashParam. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptSignHash(IntPtr hHash, uint dwKeySpec, StringBuilder sDescription,
			uint dwFlags, byte[] pbSignature, ref uint pdwSigLen)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptSignHash(hHash, dwKeySpec, sDescription, dwFlags, pbSignature, ref pdwSigLen);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptSignHash(hHash, dwKeySpec, sDescription, dwFlags, pbSignature, ref pdwSigLen);
			else
				throw new Exception($"CryptSignHash. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptCreateHash(IntPtr hProv, uint Algid, IntPtr hKey, uint dwFlags, ref IntPtr phHash)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptCreateHash(hProv, Algid, hKey, dwFlags, ref phHash);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptCreateHash(hProv, Algid, hKey, dwFlags, ref phHash);
			else
				throw new Exception($"CryptCreateHash. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция CryptAcquireContext используется для получения дескриптора к конкретному контейнеру ключей в конкретном поставщике криптографических услуг (CSP).
		/// </summary>
		/// <param name="hProv"></param>
		/// <param name="pszContainer"></param>
		/// <param name="pszProvider"></param>
		/// <param name="dwProvType"></param>
		/// <param name="dwFlags"></param>
		/// <returns></returns>
		internal static bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptAcquireContext(ref hProv, pszContainer, pszProvider, dwProvType, dwFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptAcquireContext(ref hProv, pszContainer, pszProvider, dwProvType, dwFlags);
			else
				throw new Exception($"CryptAcquireContext. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptGetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
			else
				throw new Exception($"CryptGetHashParam. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptHashData(IntPtr hHash, byte[] pbData, uint dwDataLen, uint dwFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
			else
				throw new Exception($"CryptHashData. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция CryptDestroyHash уничтожает объект функции хеширования, ссылающийся на параметр hHash. 
		/// После того, как объект функции хеширования уничтожен, он не может больше использоваться.
		/// </summary>
		/// <param name="pHashCtx"></param>
		/// <returns></returns>
		internal static bool CryptDestroyHash(IntPtr pHashCtx)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptDestroyHash(pHashCtx);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptDestroyHash(pHashCtx);
			else
				throw new Exception($"CryptDestroyHash. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		static internal bool CryptVerifyDetachedMessageSignature(
			ref CRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
			int dwSignerIndex,
			byte[] pbDetachedSignBlob,
			int cbDetachedSignBlob,
			int cToBeSigned,
			IntPtr[] rgpbToBeSigned,
			int[] rgcbToBeSigned,
			IntPtr ppSignerCert
		)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptVerifyDetachedMessageSignature(ref pVerifyPara, dwSignerIndex, pbDetachedSignBlob, cbDetachedSignBlob, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, ppSignerCert);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptVerifyDetachedMessageSignature(ref pVerifyPara, dwSignerIndex, pbDetachedSignBlob, cbDetachedSignBlob, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, ppSignerCert);
			else
				throw new Exception($"CryptVerifyDetachedMessageSignature. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция CryptFindOIDInfo получает первую предопределенную или зарегистрированную структуру CRYPT_OID_INFO, 
		/// согласованную с определенным типом ключа и с ключем. Поиск может быть ограничен идентификаторами объекта, 
		/// принадлежащими определенной группе идентификаторов объекта.
		/// </summary>
		/// <param name="dwKeyType"></param>
		/// <param name="pvKey"></param>
		/// <param name="dwGroupId"></param>
		/// <returns></returns>
		internal static IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, IntPtr pvKey, OidGroup dwGroupId)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptFindOIDInfo(dwKeyType, pvKey, dwGroupId);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptFindOIDInfo(dwKeyType, pvKey, dwGroupId);
			else
				throw new Exception($"CryptFindOIDInfo. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция CryptFindOIDInfo получает первую предопределенную или зарегистрированную структуру CRYPT_OID_INFO, 
		/// согласованную с определенным типом ключа и с ключем. Поиск может быть ограничен идентификаторами объекта, 
		/// принадлежащими определенной группе идентификаторов объекта.
		/// </summary>
		/// <param name="dwKeyType"></param>
		/// <param name="pvKey"></param>
		/// <param name="dwGroupId"></param>
		/// <returns></returns>
		internal static IntPtr CryptFindOIDInfo(OidKeyType dwKeyType, String pvKey, OidGroup dwGroupId)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptFindOIDInfo(dwKeyType, pvKey, dwGroupId);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptFindOIDInfo(dwKeyType, pvKey, dwGroupId);
			else
				throw new Exception($"CryptFindOIDInfo. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция открывает хранилище сертификатов
		/// </summary>
		/// <param name="lpszStoreProvider"></param>
		/// <param name="dwMsgAndCertEncodingType"></param>
		/// <param name="hCryptProv"></param>
		/// <param name="dwFlags"></param>
		/// <param name="pvPara"></param>
		/// <returns></returns>
		internal static IntPtr CertOpenStore(uint lpszStoreProvider, uint dwMsgAndCertEncodingType, IntPtr hCryptProv, uint dwFlags, string pvPara)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara);
			else
				throw new Exception($"CertOpenStore. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция закрывает хранилище сертификатов
		/// </summary>
		/// <param name="_hCertStore"></param>
		/// <param name="_iFlags"></param>
		/// <returns></returns>
		internal static bool CertCloseStore(IntPtr _hCertStore, uint _iFlags)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CertCloseStore(_hCertStore, _iFlags);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CertCloseStore(_hCertStore, _iFlags);
			else
				throw new Exception($"CertCloseStore. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static IntPtr CertFindCertificateInStore(IntPtr hCertStore, uint dwCertEncodingType, uint dwFindFlags, uint dwFindType,
			ref CApiExtConst.CRYPT_HASH_BLOB pvFindPara,
			IntPtr pPrevCertContext
		)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, ref pvFindPara, pPrevCertContext);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, ref pvFindPara, pPrevCertContext);
			else
				throw new Exception($"CertFindCertificateInStore. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

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
		internal static bool CryptSignMessage(ref CApiExtConst.CRYPT_SIGN_MESSAGE_PARA pSignPara, bool fDetachedSignature, uint cToBeSigned,
			IntPtr[] rgpbToBeSigned,
			uint[] rgcbToBeSigned,
			byte[] pbSignedBlob,
			ref uint pcbSignedBlob
		)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CryptSignMessage(ref pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, ref pcbSignedBlob);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CryptSignMessage(ref pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, ref pcbSignedBlob);
			else
				throw new Exception($"CryptSignMessage. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция дублирует контекст сертификата
		/// </summary>
		/// <param name="pCertContext"></param>
		/// <returns></returns>
		internal static IntPtr CertDuplicateCertificateContext(IntPtr pCertContext)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				return CApiExtUnixCryptoPro.CertDuplicateCertificateContext(pCertContext);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				return CApiExtUnixVipNet.CertDuplicateCertificateContext(pCertContext);
			else
				throw new Exception($"CertDuplicateCertificateContext. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}

		/// <summary>
		/// Функция освобождает контекст сертификата, уменьшая счетчик ссылок на единицу. 
		/// Когда счетчик ссылок обнуляется, функция освобождает память, выделенную под контекст сертификата.
		/// </summary>
		/// <param name="hPrev"></param>
		internal static void CertFreeCertificateContext(IntPtr hPrev)
		{
			if (SignServiceProvider.Csp == CspType.CryptoPro)
				CApiExtUnixCryptoPro.CertFreeCertificateContext(hPrev);
			else if (SignServiceProvider.Csp == CspType.VipNet)
				CApiExtUnixVipNet.CertFreeCertificateContext(hPrev);
			else
				throw new Exception($"CertFreeCertificateContext. Указан неподдерживаемый тип криптопровайдера {SignServiceProvider.Csp}.");
		}
	}
}
