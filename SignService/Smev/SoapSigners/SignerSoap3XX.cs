using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Smev.Services;
using SignService.Smev.Utils;
using SignService.Smev.SoapSigners.SignedXmlExt;
using SignService.Unix;
using SignService.Win;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;

namespace SignService.Smev.SoapSigners
{
	/// <summary>
	/// Реализация подписи XML для СМЭВ3 по схеме 1.1
	/// </summary>
	internal class SignerSoap3XX : ISignerSoap
	{
		private readonly ILogger<SignerSoap3XX> log;
		private const string xmldsigPrefix = "ds";

		private string tagForSign;
		private string tagForSignNamespaceUri = string.Empty;
		private string tagForRequestNamespaceUri = string.Empty;
		private string tagForRequest = string.Empty;

		private int idCounter = 1;
		internal Mr MrVersion { get; } = Mr.MR300;

		public SignedTag ElemForSign { get; set; } = SignedTag.Body;
		public bool SignWithId { get; set; } = true;

		/// <summary>
		/// Конструктор класса
		/// </summary>
		/// <param name="loggerFactory"></param>
		internal SignerSoap3XX(ILoggerFactory loggerFactory)
		{
			this.log = loggerFactory.CreateLogger<SignerSoap3XX>();
		}

		/// <summary>
		/// Метод подписи XML подписью органа власти
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		public XmlDocument SignMessageAsOv(XmlDocument doc, IntPtr certificate)
		{
			try
			{
				// Подписываем вложения
				log.LogDebug("Пытаемся подписать вложения.");
				doc = SignAttachmentsOv(doc, certificate);
				doc.Save("signed.xml");
			}
			catch (Exception ex)
			{
				log.LogError($"Ошибка при попытке проверить и подписать вложения в методе. {ex.Message}.");
				throw new CryptographicException($"Ошибка при попытке проверить и подписать вложения. {ex.Message}");
			}

			try
			{
				// Подписываем XML
				log.LogDebug("Пытаемся подписать XML.");
				Smev3xxSignedXml signedXml = new Smev3xxSignedXml(doc);

				ElemForSign = SignedTag.Smev3TagType;

				try
				{
					log.LogDebug($"Пытаемся найти тэг для подписи.");
					tagForSign = FindSmevTagForSign(doc);
					log.LogDebug($"Тэг для подписи: {tagForSign}.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке определить тэг для подписи. {ex.Message}.");
				}

				try
				{
					log.LogDebug("Пытаемся удалить информацию о подписи, если есть.");
					RemoveCallerInformationSystemSignature(doc.DocumentElement);
					log.LogDebug("Удаление выполнено успешно.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке удалить информацию о подписи. {ex.Message}.");
				}

				try
				{
					log.LogDebug($"Пытаемся установить значение идентификатора элемента. Флаг SignWithId: {SignWithId}.");
					SmevXmlHelper.SetElemId(doc, tagForSign, tagForSignNamespaceUri, SignWithId, MrVersion, ref idCounter, SmevMr3xxTags.InformationSystemSignatureId);
					log.LogDebug($"Установка значения идентификатора элемента выполнена успешно.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке установить идентификатор элемента. {ex.Message}.");
				}

				try
				{
					log.LogDebug($"Пытаемся добавить в XML тэг Reference.");
					signedXml = (Smev3xxSignedXml)SmevXmlHelper.AddReference(doc, signedXml, certificate,
						SignWithId, MrVersion, ElemForSign, ref idCounter, tagForSign, tagForSignNamespaceUri
					);
					log.LogDebug($"Тэг Reference успешно добавлен.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при добавлении тэга Reference. {ex.Message}.");
				}

				signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

				try
				{
					log.LogDebug($"Пытаемся получить значение SignatureMethod.");
					signedXml.SignedInfo.SignatureMethod = SignServiceUtils.GetSignatureMethod(SignServiceUtils.GetAlgId(certificate));
					log.LogDebug($"Значение SignatureMethod успешно получено: {signedXml.SignedInfo.SignatureMethod}.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при получении значения алгоритма подписи. {ex.Message}.");
				}

				try
				{
					KeyInfo keyInfo = new KeyInfo();
					X509Certificate2 cert = SignServiceUtils.GetX509Certificate2(certificate);
					keyInfo.AddClause(new KeyInfoX509Data(cert));
					signedXml.KeyInfo = keyInfo;
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при формировании элемента KeyInfo. {ex.Message}.");
				}

				try
				{
					log.LogDebug($"Пытаемся вычислить подпись.");
					signedXml.ComputeSignatureWithoutPrivateKey(xmldsigPrefix, certificate);
					log.LogDebug($"Вычисление подписи выполнено успешно.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке вычислить подпись для XML. {ex.Message}.");
				}

				XmlElement signatureElem = null;
				XmlElement sysSignature = null;

				try
				{
					log.LogDebug("Пытаемся получить элемент с подписью.");
					signatureElem = signedXml.GetXml(xmldsigPrefix);
					log.LogDebug("Элемент с подписью успешно получен.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке получить элемент содержащий подпись. {ex.Message}.");
				}

				string prefix = FindPrefix(doc.DocumentElement, false);

				try
				{
					log.LogDebug("Заполняем объект sysSignature элементом в с подписью и префиксом.");

					if (!string.IsNullOrEmpty(prefix))
					{
						sysSignature = doc.CreateElement(prefix, SignatureTags.CallerInformationSystemSignatureTag, SignatureTags.CallerInformationSystemSignatureNamespace);
						sysSignature.PrependChild(doc.ImportNode(signatureElem, true));
					}
					else
					{
						sysSignature = doc.CreateElement("", SignatureTags.CallerInformationSystemSignatureTag, SignatureTags.CallerInformationSystemSignatureNamespace);
						sysSignature.PrependChild(doc.ImportNode(signatureElem, true));
					}

					log.LogDebug("Заполнение объекта sysSignature успешно выполнено.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке сформировать элемент sysSignature. {ex.Message}.");
				}

				try
				{
					log.LogDebug("Пытаемся добавить подпись в XML содержимое.");
					FillSignatureElement(doc, sysSignature, certificate, tagForRequest, tagForRequestNamespaceUri, true);
					log.LogDebug("Подпись успешно добавлена.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при попытке заполнить XML информацией о подписи. {ex.Message}.");
				}

				return doc;
			}
			catch(Exception ex)
			{
				log.LogError($"Ошибка при попытке подписать XML. {ex.Message}.");
				throw new CryptographicException($"Ошибка при попытке подписать XML для версии МР300. {ex.Message}.");
			}
			finally
			{
				SignServiceUtils.FreeHandleCertificate(certificate);
			}
		}

		/// <summary>
		/// Метод нахождения префикса
		/// </summary>
		/// <param name="element"></param>
		/// <param name="isTypeBasic"></param>
		/// <returns></returns>
		private string FindPrefix(XmlElement element, bool isTypeBasic)
		{
			try
			{
				log.LogDebug("Пытаемся получить значение префикса.");

				string prefix = SoapDSigUtil.FindPrefix(element, NamespaceUri.Smev3Types);
				if (!isTypeBasic)
				{
					prefix = (string.Compare(prefix, "xmlns", StringComparison.InvariantCultureIgnoreCase) == 0) ? string.Empty : prefix;
				}
				else
				{
					prefix = (string.IsNullOrEmpty(prefix) || string.Compare(prefix, "xmlns", true) == 0) ? "typesBasic" : prefix;
				}

				log.LogDebug($"Значение префикса успешно получено: {prefix}.");

				return prefix;
			}
			catch (Exception ex)
			{
				throw new Exception($"Ошибка при попытке получить значение префикса. {ex.Message}.");
			}
		}

		/// <summary>
		/// Метод подписания вложений подписью органа власти
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		private XmlDocument SignAttachmentsOv(XmlDocument doc, IntPtr certificate)
		{
			XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);

			string prefix = FindPrefix(doc.DocumentElement, true);

			nsmgr.AddNamespace(prefix, NamespaceUri.Smev3TypesBasic);

			log.LogDebug($"Пытаемся найти тэг заголовка вложений.");
			string findHeaderString = string.Format("//{0}:AttachmentHeaderList", prefix);
			XmlElement attachmentHeaderList = doc.SelectSingleNode(findHeaderString, nsmgr) as XmlElement;

			log.LogDebug($"Пытаемся найти тэг с контентом вложений.");
			string findContentString = string.Format("//{0}:AttachmentContentList", prefix);
			XmlElement attachmentContentList = doc.SelectSingleNode(findContentString, nsmgr) as XmlElement;

			if (attachmentHeaderList != null && attachmentContentList != null)
			{
				log.LogDebug("Список заголовков и контента с вложениями был успешно получен.");

				bool changed = false;
				AttachmentHeaderList headerList = null;

				try
				{
					log.LogDebug("Пытаемся получить объект AttachmentHeaderList.");
					headerList = DeserializeXml<AttachmentHeaderList>(attachmentHeaderList, NamespaceUri.Smev3TypesBasic);
					log.LogDebug("Объект AttachmentHeaderList успешно получен.");
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при получении объекта AttachmentHeaderList. {ex.Message}.");
				}

				// Если нет информации о вложениях
				if(headerList == null || headerList.AttachmentHeader == null || headerList.AttachmentHeader.Length <= 0)
				{
					log.LogDebug("Вложения для подписи не найдены.");
					return doc;
				}

				// Проверим есть ли вложения для которых необходима подпись
				log.LogDebug("Проверим есть ли вложения для которых необходима подпись.");

				var needSigned = false;
				foreach (var header in headerList.AttachmentHeader)
				{
					if(header.SignaturePKCS7 == null || header.SignaturePKCS7.Length <= 0)
					{
						log.LogDebug($"Вложение {header.contentId} нуждается в подписи.");
						needSigned = true;
						break;
					}
				}

				// Если все вложения уже подписаны, выходим
				if (!needSigned)
				{
					log.LogDebug("Все вложения являются подписанными.");
					return doc;
				}

				// Пытаемся получить список контента вложений. Обрабатывает только вложения указанные в XML в виде base64 строки, для случаев с
				// расположением вложения на FTP или в случае если данный XML является частью МТОМ запроса предполагается что вложения были подписаны отдельно, заранее
				AttachmentContentList contentList = null;

				try
				{
					contentList = DeserializeXml<AttachmentContentList>(attachmentContentList, NamespaceUri.Smev3TypesBasic);
				}
				catch(Exception ex)
				{
					throw new Exception($"Ошибка при десериализации контента вложений. " +
						$"Убедитесь, что для вложений, которые находятся на FTP, или будут расположены в МТОМ запросе подпись была получена отдельно. " +
						$"Содержимое ошибки {ex.Message}.");
				}

				if (contentList != null && contentList.AttachmentContent != null && contentList.AttachmentContent.Length > 0)
				{
					foreach (AttachmentHeaderType header in headerList.AttachmentHeader)
					{
						if (header.SignaturePKCS7 == null || header.SignaturePKCS7.Length == 0)
						{
							log.LogDebug($"В заголовке вложения отсутствует подпись. Пытаемся подписать.");
							AttachmentContentType content = contentList.AttachmentContent.FirstOrDefault(cnt => cnt.Id == header.contentId);

							if (content != null && content.Content != null && content.Content.Length > 0)
							{
								byte[] signature = null;

								try
								{
									if (SignServiceUtils.IsUnix)
									{
										log.LogDebug($"Выполняем подпись под Unix платформой.");
										signature = SignServiceUnix.Sign(content.Content, certificate);
									}
									else
									{
										log.LogDebug($"Выполняем подпись под Windows платформой.");
										signature = SignServiceWin.Sign(content.Content, certificate);
									}
								}
								catch(Exception ex)
								{
									throw new Exception($"Ошибка при вычислении подписи для вложения. {ex.Message}.");
								}

								header.SignaturePKCS7 = signature;
								changed = true;
							}
						}
					}

					if (changed)
					{
						string prefixForSerialize = FindPrefix(doc.DocumentElement, false);

						try
						{
							log.LogDebug($"Пытаемся обновить список вложений.");

							XmlElement attachmentHeaderListNew = this.SerializeToXmlElement(headerList, NamespaceUri.Smev3TypesBasic, prefixForSerialize);
							attachmentHeaderListNew = doc.ImportNode(attachmentHeaderListNew, true) as XmlElement;
							attachmentHeaderList.ParentNode.ReplaceChild(attachmentHeaderListNew, attachmentHeaderList);

							log.LogDebug("Список вложений успешно обновлен.");
						}
						catch(Exception ex)
						{
							throw new Exception($"Ошибка при попытке обновить подписанные вложения. {ex.Message}.");
						}
					}
				}
			}

			return doc;
		}

		/// <summary>
		/// Метод сериализации XML элемента, используется для обновления списка вложений
		/// </summary>
		/// <param name="o"></param>
		/// <param name="objectnamespace"></param>
		/// <param name="prefixForSerialize"></param>
		/// <returns></returns>
		private XmlElement SerializeToXmlElement(object o, string objectnamespace, string prefixForSerialize)
		{
			XmlDocument doc = new XmlDocument();

			XmlSerializerNamespaces xsnss = new XmlSerializerNamespaces();
			xsnss.Add(prefixForSerialize, objectnamespace);

			using (XmlWriter writer = doc.CreateNavigator().AppendChild())
			{
				new XmlSerializer(o.GetType(), objectnamespace).Serialize(writer, o, xsnss);
			}

			var docElement = doc.DocumentElement;

			for (int i = docElement.Attributes.Count - 1; i >= 0; i--)
			{
				XmlAttribute tmpAtt = docElement.Attributes[i];

				if (tmpAtt.LocalName == "xsi" && tmpAtt.Value == "http://www.w3.org/2001/XMLSchema-instance")
				{
					docElement.RemoveAttributeAt(i);
					//docElement.RemoveAttribute(tmpAtt.LocalName, tmpAtt.NamespaceURI);
				}
				else if (tmpAtt.LocalName == "xsd" && tmpAtt.Value == "http://www.w3.org/2001/XMLSchema")
				{
					docElement.RemoveAttributeAt(i);
					//docElement.RemoveAttribute(tmpAtt.LocalName, tmpAtt.NamespaceURI);
				}
				else if (tmpAtt.LocalName == "xmlns" && string.IsNullOrEmpty(tmpAtt.Value))
				{
					docElement.RemoveAttributeAt(i);
					//docElement.RemoveAttribute(tmpAtt.LocalName, tmpAtt.NamespaceURI);
				}
			}

			return docElement;
		}

		/// <summary>
		/// Добавляет тэг с подписью целиком. Сертификат должен быть в тэге подписи.
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="signedXml"></param>
		/// <param name="certificate"></param>
		/// <param name="tag"></param>
		/// <param name="namespaceUri"></param>
		/// <param name="fillInTheEnd">Прикрепить подпись в конец?</param>
		private void FillSignatureElement(XmlDocument doc, XmlElement signatureElem, IntPtr certificate, string tag, string namespaceUri, bool fillInTheEnd)
		{
			XmlElement tagElem = (XmlElement)doc.GetElementsByTagName(tag, namespaceUri)[0];
			if (fillInTheEnd)
			{
				tagElem.AppendChild(doc.ImportNode(signatureElem, true));
			}
			else
			{
				tagElem.PrependChild(doc.ImportNode(signatureElem, true));
			}
		}

		/// <summary>
		/// Метод поиска тэга в который необходимо добавить подпись
		/// </summary>
		/// <param name="doc"></param>
		/// <returns></returns>
		private string FindSmevTagForSign(XmlDocument doc)
		{
			string result = string.Empty;

			tagForSignNamespaceUri = NamespaceUri.Smev3Types;
			string[] tagNames = SmevMr3xxTags.GetAllRequestTags();

			string baseTagName = string.Empty;
			XmlElement basetElem = null;

			if (tagNames != null)
			{
				for (int elemCounter = 0; (elemCounter < tagNames.Length) && (string.IsNullOrEmpty(baseTagName)); elemCounter++)
				{
					string elemName = tagNames[elemCounter];
					string lowerName = elemName.ToLower();

					tagForSignNamespaceUri = SmevMr3xxTags.GetNamespaceTagByTag(elemName);

					basetElem = (XmlElement)doc.GetElementsByTagName(elemName, tagForSignNamespaceUri)[0] ??
									(XmlElement)doc.GetElementsByTagName(lowerName, tagForSignNamespaceUri)[0];
					if (basetElem != null)
					{
						baseTagName = elemName;
					}
				}
			}

			tagForRequest = baseTagName;
			tagForRequestNamespaceUri = tagForSignNamespaceUri;
			tagForSignNamespaceUri = NamespaceUri.Smev3TypesBasic;
			tagNames = SmevMr3xxTags.GetSignTagByRequestTag(baseTagName);

			XmlElement targetElem = null;

			if (tagNames != null)
			{
				for (int elemCounter = 0; (elemCounter < tagNames.Length) && (string.IsNullOrEmpty(result)); elemCounter++)
				{
					string elemName = tagNames[elemCounter];
					string lowerName = elemName.ToLower();

					tagForSignNamespaceUri = SmevMr3xxTags.GetNamespaceTagByTag(elemName);

					targetElem = (XmlElement)doc.GetElementsByTagName(elemName, tagForSignNamespaceUri)[0] ??
									(XmlElement)doc.GetElementsByTagName(lowerName, tagForSignNamespaceUri)[0];
					if (targetElem != null)
					{
						result = elemName;
					}
				}
			}

			return result;
		}

		/// <summary>
		/// Удаление тэгов CallerInformationSystemSignature (подпись) из запроса.
		/// </summary>
		/// <param name="node">Тэг из которого надо убрать все подписи.</param>
		private void RemoveCallerInformationSystemSignature(XmlElement node)
		{
			// Получаем тэги Security.
			XmlNodeList nodeList = node.GetElementsByTagName(SignatureTags.CallerInformationSystemSignatureTag,
				SignatureTags.CallerInformationSystemSignatureNamespace);
			SmevXmlHelper.RemoveNodes(node, nodeList);
		}

		/// <summary>
		/// Метод запускает процесс десериализации для XML содержимого описывающего вложения
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="toDeserialize"></param>
		/// <param name="xmlns"></param>
		/// <returns></returns>
		private T DeserializeXml<T>(XmlElement toDeserialize, string xmlns = null)
		{
			if (toDeserialize == null)
			{
				return default(T);
			}

			if (string.IsNullOrEmpty(xmlns))
			{
				xmlns = toDeserialize.NamespaceURI;
			}

			return DeserializeXml<T>(toDeserialize.OuterXml, xmlns);
		}

		/// <summary>
		/// Метод десериализует XML содержимое описывающее вложения в объекты вида AttachmentHeaderList/AttachmentContentList
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="toDeserialize"></param>
		/// <param name="xmlns"></param>
		/// <returns></returns>
		private T DeserializeXml<T>(string toDeserialize, string xmlns)
		{
			T wrapper = default(T);

			if (string.IsNullOrEmpty(toDeserialize))
			{
				return wrapper;
			}

			XmlSerializer ser = new XmlSerializer(typeof(T), xmlns);
			var reader = new StringReader(toDeserialize);
			wrapper = (T)ser.Deserialize(reader);

			return wrapper;
		}
	}
}
