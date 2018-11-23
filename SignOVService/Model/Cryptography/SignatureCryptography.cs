using System;
using System.IO;

namespace SignOVService.Model.Cryptography
{
	public class SignatureCryptography
	{
		readonly object _locker = new object();
		readonly CryptoProvider crypto = new CryptoProvider();

		public SignatureCryptography()
		{

		}

		/// <summary>
		/// Подписать байты с выбором сертификата.
		/// </summary>
		/// <param name="bytes">Байты для подписи.</param>
		/// <param name="certificate">Сертификат, которым требуется подписать данные.</param>
		/// <returns>Байты - подпись.</returns>
		public byte[] SignWithCertificate(Stream bytes, IntPtr certificate)
		{
			return ComputeSignature(bytes, certificate);
		}

		/// <summary>
		/// Подписать поток указанным сертификатом.
		/// </summary>
		/// <param name="stream">Поток который надо подписать.</param>
		/// <param name="certificate">Сертификат, которым надо подписать.</param>
		/// <returns>Байты-подпись.</returns>
		private byte[] ComputeSignature(Stream stream, IntPtr certificate)
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
		private byte[] ComputeSignatureStreamFromFramework(Stream stream, IntPtr certificate)
		{
			byte[] result = null;

			lock (_locker)
			{
				if (certificate != null)
				{
					try
					{
						MemoryStream memoryData = stream as MemoryStream;
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

						return crypto.Sign(content, certificate);
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
		private byte[] ComputeSignatureStreamFromFramework(BinaryReader streamSourceReader, IntPtr certificate)
		{
			return ComputeSignatureStreamFromFramework(streamSourceReader.BaseStream, certificate);
		}
	}
}
