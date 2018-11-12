using System;

namespace SignOVService.Model.Cryptography
{
	public class UCConst
	{
		/// <summary>
		// Создает хранилище сертификатов в кэшированной памяти.
		// В хранилище изначально не загружаются сертификаты, списки отзыва сертификатов (CRL) или списки доверия сертификатов (CTL).
		// Обычно используется для создания временного хранилища.
		// Любое добавление сертификатов, CRL или CTL или изменений в свойствах сертификатов, 
		// CRL или CTL в хранилище не сохраняются автоматически.Они могут быть сохранены в файл или в BLOB памяти с помощью CertSaveStore.
		/// </summary>
		internal const uint CERT_STORE_PROV_MEMORY = 2;

		/// <summary>
		// Инициализирует хранилище с сертификатами, CRL и CTL из закодированного сообщения PKCS № 7.
		// Параметр dwEncodingType должен указывать типы кодирования, которые будут использоваться как с сообщениями, так и с сертификатами.
		// pvPara значение: В pvPara параметр указывает на CRYPT_DATA_BLOB структурукоторая представляет собой закодированное сообщение.
		/// </summary>
		internal const uint CERT_STORE_PROV_PKCS7 = 5;

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

		/// <summary>
		/// Открывает хранилище, которое будет сборкой других хранилище. 
		/// Хранилища добавляются или удаляются из коллекции с помощью CertAddStoreToCollection и CertRemoveStoreFromCollection . 
		/// Когда хранилище добавляется в коллекцию, все сертификаты, 
		/// CRL и ЦТЛ в этом хранилище становятся доступными для поиска или перечисления магазина коллекции.
		//	Флаг dwFlags должен быть равным нулю.
		//pvPara значение:   pvPara параметр должен быть NULL
		/// </summary>
		internal const uint CERT_STORE_PROV_COLLECTION = 11;

		// cert store flags
		internal const uint CERT_STORE_READONLY_FLAG = 0x00008000;
		internal const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
		internal const uint CERT_STORE_CREATE_NEW_FLAG = 0x00002000;

		// cert encoding flags.
		internal const uint CRYPT_ASN_ENCODING = 0x00000001;
		internal const uint CRYPT_NDR_ENCODING = 0x00000002;
		internal const uint X509_ASN_ENCODING = 0x00000001;
		internal const uint X509_NDR_ENCODING = 0x00000002;
		internal const uint PKCS_7_ASN_ENCODING = 0x00010000;
		internal const uint PKCS_7_NDR_ENCODING = 0x00020000;
		internal const uint PKCS_7_OR_X509_ASN_ENCODING = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);

		internal const uint CERT_COMPARE_ANY = 0;
		internal const uint CERT_COMPARE_SHA1_HASH = 1;
		internal const uint CERT_COMPARE_NAME = 2;
		internal const uint CERT_COMPARE_MD5_HASH = 4;
		internal const uint CERT_COMPARE_PROPERTY = 5;
		internal const uint CERT_COMPARE_PUBLIC_KEY = 6;
		internal const uint CERT_COMPARE_SHIFT = 16;

		internal const uint CERT_INFO_ISSUER_FLAG = 4;
		internal const uint CERT_INFO_SUBJECT_FLAG = 7;
		internal const uint CERT_COMPARE_NAME_STR_A = 7;
		internal const uint CERT_COMPARE_EXISTING = 13;
		internal const uint CERT_COMPARE_ENHKEY_USAGE = 10;
		internal const uint CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG = 1;

		// dwFindType CertFindCertificateInStore 
		internal const uint CERT_FIND_ANY = ((int)CERT_COMPARE_ANY << (int)CERT_COMPARE_SHIFT);
		internal const uint CERT_FIND_SHA1_HASH = ((int)CERT_COMPARE_SHA1_HASH << (int)CERT_COMPARE_SHIFT);
		internal const uint CERT_FIND_MD5_HASH = ((int)CERT_COMPARE_MD5_HASH << (int)CERT_COMPARE_SHIFT);
		internal const uint CERT_FIND_PROPERTY = ((int)CERT_COMPARE_PROPERTY << (int)CERT_COMPARE_SHIFT);
		internal const uint CERT_FIND_PUBLIC_KEY = ((int)CERT_COMPARE_PUBLIC_KEY << (int)CERT_COMPARE_SHIFT);
		internal const uint CERT_FIND_SUBJECT_NAME = ((int)CERT_COMPARE_NAME << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
		internal const uint CERT_FIND_ISSUER_NAME = ((int)CERT_COMPARE_NAME << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
		internal const uint CERT_FIND_SUBJECT_STR_A = ((int)CERT_COMPARE_NAME_STR_A << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
		internal const uint CERT_FIND_ISSUER_STR_A = ((int)CERT_COMPARE_NAME_STR_A << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
		internal const uint CERT_FIND_EXISTING = ((int)CERT_COMPARE_EXISTING << (int)CERT_COMPARE_SHIFT);
		internal const uint CERT_FIND_ENHKEY_USAGE = ((int)CERT_COMPARE_ENHKEY_USAGE << (int)CERT_COMPARE_SHIFT);
	}

	public struct CRYPTOAPI_BLOB
	{
		public int cbData;
		public IntPtr pbData;
	}
}
