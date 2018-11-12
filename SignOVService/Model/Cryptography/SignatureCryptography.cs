using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using static SignOVService.Model.Cryptography.CApiLite;

namespace SignOVService.Model.Cryptography
{
	public class SignatureCryptography
	{
		readonly object _locker = new object();

		public SignatureCryptography()
		{

		}

		/// <summary>
		/// Свойство определяет на какой ОС запущен сервис
		/// </summary>
		public static bool fIsLinux
		{
			get
			{
				int iPlatform = (int)Environment.OSVersion.Platform;
				return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
			}
		}

		/// <summary>
		/// Подписать байты с выбором сертификата.
		/// </summary>
		/// <param name="bytes">Байты для подписи.</param>
		/// <param name="certificate">Сертификат, которым требуется подписать данные.</param>
		/// <returns>Байты - подпись.</returns>
		public byte[] SignWithCertificate(Stream bytes, X509Certificate2 certificate)
		{
			return Sign(bytes, certificate);
		}

		/// <summary>
		/// Подписать байты указанным сертификатом.
		/// </summary>
		/// <param name="data"></param>
		/// <param name="cert"></param>
		/// <returns></returns>
		public byte[] SignWithApi(byte[] data, X509Certificate2 cert)
		{
			// Структура содержит информацию для подписания сообщений с использованием указанного контекста сертификата подписи
			CRYPT_SIGN_MESSAGE_PARA pParams = new CRYPT_SIGN_MESSAGE_PARA
			{
				// Размер этой структуры в байтах
				cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_SIGN_MESSAGE_PARA)),
				// Используемый тип кодирования
				dwMsgEncodingType = (int)(UCConst.PKCS_7_OR_X509_ASN_ENCODING),
				// Указатель на CERT_CONTEXT, который будет использоваться при подписании. 
				// Для того чтобы контекст предоставил доступ к закрытому сигнатурному ключу,
				// необходимо установить свойство CERT_KEY_PROV_INFO_PROP_ID или CERT_KEY_CONTEXT_PROP_ID
				pSigningCert = cert.Handle,

				// Количество элементов в rgpMsgCert массиве CERT_CONTEXT структур.Если установлено ноль,
				// в подписанное сообщение не включаются сертификаты.
				cMsgCert = 1
			};

			//Содержащий алгоритм хеширования, используемый для хеширования данных, подлежащих подписке.
			pParams.HashAlgorithm.pszObjId = cert.SignatureAlgorithm.Value;

			// Массив указателей на буферы, содержащие содержимое, подлежащее подписке.
			IntPtr rgpbToBeSigned = Marshal.AllocHGlobal(data.Length);

			// Выделяем память под хранение сертификата
			GCHandle pGC = GCHandle.Alloc(cert.Handle, GCHandleType.Pinned);

			try
			{
				// Массив указателей на контексты сертификатов для включения в подписанное сообщение. 
				// Если хотим использовать сертификат для подписания, указатель на него должен быть в массиве rgpMsgCert.
				pParams.rgpMsgCert = pGC.AddrOfPinnedObject();
				Marshal.Copy(data, 0, rgpbToBeSigned, data.Length);

				/*
					Метод CryptSignMessage не работает в режиме двух вызовов, характерного для большинства библиотечных методов, 
					работающих с большими блоками памяти (первый с null — выдает необходимую длину буфера, второй заполняет буфер). 
					Поэтому необходимо создать большой буфер, а затем укоротить его по реальной длине.
				 */

				// Указатель, определяющий размер в байтах буфера signArray . 
				// Когда функция возвращается, эта переменная содержит размер в байтах подписанного и закодированного сообщения.
				uint signArrayLength = 50000;

				// Указатель на буфер , для получения кодированного подписанного хэш, если detached является значение TRUE , 
				// или как кодированного контента и подписанного хэша , если detached является FALSE.
				byte[] signArray = new byte[signArrayLength];

				// TRUE, если это должна быть отдельная подпись, Если для этого параметра установлено значение TRUE , в pbSignedBlob кодируется только подписанный хеш . 
				// В противном случае кодируются как rgpbToBeSigned, так и подписанный хеш.
				bool detached = true;

				// Количество элементов массива в rgpbToBeSigned.
				// Этот параметр должен быть установлен в единицу, если для параметра fDetachedSignature установлено значение TRUE
				uint cToBeSigned = 1;

				// Подписываем данные
				// new uint[1] { (uint)data.Length } - Массив размеров в байтах буферов содержимого, на которые указывает rgpbToBeSigned
				if (!CryptSignMessage(ref pParams, detached, cToBeSigned, new IntPtr[1] { rgpbToBeSigned }, new uint[1] { (uint)data.Length }, signArray, ref signArrayLength))
				{
					throw new Exception("Ошибка при подписании данных. Метод CryptSignMessage вернул false.");
				}

				// Укорачиваем массив по его реальной длине
				Array.Resize(ref signArray, (int)signArrayLength);

				return signArray;
			}
			catch (Exception ex)
			{
				throw ex;
			}
			finally
			{
				// Освобождаем занимаемую память
				pGC.Free();
				Marshal.FreeHGlobal(rgpbToBeSigned);
			}
		}

		/// <summary>
		/// Подписать байты указанным сертификатом.
		/// </summary>
		/// <param name="stream">Поток для подписи.</param>
		/// <param name="certificate">Сертификат, которым надо подписать.</param>
		/// <returns>Байты-подпись.</returns>
		public byte[] Sign(Stream stream, X509Certificate2 certificate)
		{
			return ComputeSignature(stream, certificate);
		}

		/// <summary>
		///     Подписать поток указанным сертификатом.
		/// </summary>
		/// <param name="stream">Поток который надо подписать.</param>
		/// <param name="certificate">Сертификат, которым надо подписать.</param>
		/// <returns>Байты-подпись.</returns>
		private byte[] ComputeSignature(Stream stream, X509Certificate2 certificate)
		{
			byte[] result = null;

			if (stream == null)
				return null;

			try
			{
				// Сделано для задачи RDC-1142 (imironov). Ошибка из-за использования InflaterInputStream.
				// Поток должен поддерживать seeking, иначе упадет проверка. Если нет, то пробуем завернуть в MemoryStream.
				// Если поток не поддерживает seeking, то Length будет равна 0.
				if (stream.CanSeek == false)
				{
					if (stream.Length == 0)
					{
						// Бывают потоки, которые не умеют отдавать Length.
						using (Stream dataFromNonLength = new MemoryStream())
						{
							stream.CopyTo(dataFromNonLength);
							dataFromNonLength.Position = 0;
							if (dataFromNonLength.Length == 0)
							{
								using (Stream streamNull = new MemoryStream(new byte[] { 0 }))
								{
									result = ComputeSignatureStreamFromFramework(streamNull, certificate);
								}
							}
							else
							{
								result = ComputeSignatureStreamFromFramework(dataFromNonLength, certificate);
							}
						}
					}
					else
					{
						using (BinaryReader dataReader = new BinaryReader(stream))
						{
							result = ComputeSignatureStreamFromFramework(dataReader, certificate);
						}
					}
				}
				else if (stream.Length == 0)
				{
					using (Stream streamNull = new MemoryStream(new byte[] { 0 }))
					{
						result = ComputeSignatureStreamFromFramework(streamNull, certificate);
					}
				}
				else
				{
					result = ComputeSignatureStreamFromFramework(stream, certificate);
				}
			}
			catch (Exception ex)
			{
				throw ex;
			}

			return result;
		}

		/// <summary>
		/// Подписать поток указанным сертификатом.
		/// </summary>
		/// <param name="streamSourceReader">Поток который надо подписать.</param>
		/// <param name="certificate">Сертификат, которым надо подписать.</param>
		/// <returns>Байты-подпись.</returns>
		private byte[] ComputeSignatureStreamFromFramework(Stream stream, X509Certificate2 certificate)
		{
			byte[] result = null;

			lock (_locker)
			{
				if (certificate != null)
				{
					try
					{
						var memoryData = stream as MemoryStream;
						byte[] content = null;

						if (memoryData != null)
						{
							content = memoryData.ToArray();
						}
						else
						{
							memoryData = new MemoryStream();
							stream.CopyTo(memoryData);
							content = memoryData.ToArray();
						}

						return SignWithApi(content, certificate);
						//// Что подписываем
						//ContentInfo contentInfo = new ContentInfo(content);

						//// Чем подписываем
						//CmsSigner signer = new CmsSigner(certificate);

						//// Экземпляр класса, выполняющего подписание
						//SignedCms cms = new SignedCms(contentInfo);

						//// Подписываем
						//cms.ComputeSignature(signer);

						//// Возвращаем входящие данные с подписью в виде массива байт
						//return cms.Encode();
					}
					catch (Exception ex)
					{
						throw ex;
					}
				}
			}

			return result;
		}

		/// <summary>
		/// Подписать поток указанным сертификатом.
		/// </summary>
		/// <param name="streamSourceReader">Поток который надо подписать.</param>
		/// <param name="certificate">Сертификат, которым надо подписать.</param>
		/// <returns>Байты-подпись.</returns>
		private byte[] ComputeSignatureStreamFromFramework(BinaryReader streamSourceReader, X509Certificate2 certificate)
		{
			return ComputeSignatureStreamFromFramework(streamSourceReader.BaseStream, certificate);
		}
	}
}
