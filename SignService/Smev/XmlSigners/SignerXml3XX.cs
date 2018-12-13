using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Smev.Services;
using SignService.Smev.SmevTransform;
using SignService.Smev.Utils;
using SignService.Smev.XmlSigners.SignedXmlExt;
using SignService.Unix;
using SignService.Unix.Api;
using SignService.Win;
using SignService.Win.Api;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;

namespace SignService.Smev.XmlSigners
{
	internal class SignerXml3XX : ISignerXml
	{
		private readonly ILogger<SignerXml3XX> log;

		private const string XmlDsigGost3410UrlObsolete =  "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
		private const string XmlDsigGost3410_2012_256UrlObsolete = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
		private const string XmlDsigGost3411UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
		private const string XmlDsigSha1UrlObsolete = "http://www.w3.org/2000/09/xmldsig#sha1";
		private const string xmldsigPrefix = "ds";

		private readonly string mrNamespace;
		private readonly string securityNamespace;
		
		private string tagForSign;
		private string tagForSignNamespaceUri = string.Empty;
		private string tagForRequestNamespaceUri = string.Empty;
		private string tagForRequest = string.Empty;

		private int idCounter = 1;

		internal SignedTag ElemForSign { get; set; } = SignedTag.Body;
		internal bool SignWithId { get; set; } = true;
		internal Mr MrVersion { get; }

		SignedTag ISignerXml.ElemForSign { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
		bool ISignerXml.SignWithId { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

		public SignerXml3XX(ILoggerFactory loggerFactory)
		{
			this.log = loggerFactory.CreateLogger<SignerXml3XX>();
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
				log.LogError($"Ошибка при попытке проверить и подписать вложения. {ex.Message}.");
				throw new CryptographicException("Ошибка при попытке проверить и подписать вложения", ex);
			}

			try
			{
				log.LogDebug("Пытаемся подписать XML.");
				Smev3xxSignedXml signedXml = new Smev3xxSignedXml(doc);

				ElemForSign = SignedTag.Smev3TagType;

				log.LogDebug($"Пытаемся найти тэг для подписи.");
				tagForSign = FindSmevTagForSign(doc);
				log.LogDebug($"Тэг для подписи: {tagForSign}.");

				log.LogDebug("Пытаемся удалить информацию о подписи, если есть.");
				RemoveCallerInformationSystemSignature(doc.DocumentElement);
				SetElemId(doc, tagForSign, tagForSignNamespaceUri, SmevMr3xxTags.InformationSystemSignatureId);

				signedXml = (Smev3xxSignedXml)AddReference(doc, signedXml, certificate);
				signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

				log.LogDebug($"Пытаемся получить значение SignatureMethod.");
				signedXml.SignedInfo.SignatureMethod = SignServiceUtils.GetSignatureMethod(SignServiceUtils.GetAlgId(certificate));
				log.LogDebug($"Значение SignatureMethod успешно получено: {signedXml.SignedInfo.SignatureMethod}.");

				KeyInfo keyInfo = new KeyInfo();

				log.LogDebug("Пытаемся получить информацию о сертификате.");
				X509Certificate2 cert = SignServiceUtils.GetX509Certificate2(certificate);
				log.LogDebug($"Информация о сертификате успешно получена. Владелец сертификата: {cert.SubjectName}.");

				keyInfo.AddClause(new KeyInfoX509Data(cert));
				signedXml.KeyInfo = keyInfo;

				log.LogDebug($"Пытаемся вычислить подпись.");
				signedXml.ComputeSignatureWithoutPrivateKey(xmldsigPrefix, certificate);
				log.LogDebug($"Подпись успешно получена.");

				// Получаем подписанный элемент
				XmlElement signatureElem = signedXml.GetXml(xmldsigPrefix);

				log.LogDebug("Пытаемся получить значение prefix.");
				string prefix = SoapDSigUtil.FindPrefix(doc.DocumentElement, NamespaceUri.Smev3Types);

				XmlElement sysSignature = null;

				if (string.Compare(prefix, "xmlns", StringComparison.InvariantCultureIgnoreCase) == 0)
				{
					prefix = string.Empty;
				}

				log.LogDebug($"Значение prefix: {prefix}.");

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

				log.LogDebug("Пытаемся добавить подпись в XML содержимое.");
				FillSignatureElement(doc, sysSignature, certificate, tagForRequest, tagForRequestNamespaceUri, true);
				log.LogDebug("Подпись успешно добавлена.");

				SignServiceUtils.FreeHandleCertificate(certificate);

				return doc;
			}
			catch(Exception ex)
			{
				log.LogError($"Ошибка при попытке подписать XML. {ex.Message}.");
				throw new CryptographicException($"Ошибка при попытке подписать XML. {ex.Message}.");
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

			log.LogDebug("Пытаемся получить prefix.");
			string prefix = SoapDSigUtil.FindPrefix(doc.DocumentElement, NamespaceUri.Smev3TypesBasic);

			if (string.IsNullOrEmpty(prefix) || string.Compare(prefix, "xmlns", true) == 0)
			{
				prefix = "typesBasic";
			}

			log.LogDebug($"Полученный prefix: {prefix}.");
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

				AttachmentHeaderList headerList = DeserializeXml<AttachmentHeaderList>(attachmentHeaderList, NamespaceUri.Smev3TypesBasic);
				AttachmentContentList contentList = DeserializeXml<AttachmentContentList>(attachmentContentList, NamespaceUri.Smev3TypesBasic);

				if (headerList != null && headerList.AttachmentHeader != null && headerList.AttachmentHeader.Length > 0
					&& contentList != null && contentList.AttachmentContent != null && contentList.AttachmentContent.Length > 0)
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

								header.SignaturePKCS7 = signature;
								changed = true;
							}
						}
					}

					if (changed)
					{
						log.LogDebug($"Пытаемся получить значение prefixForSerialize.");
						string prefixForSerialize = SoapDSigUtil.FindPrefix(doc.DocumentElement, NamespaceUri.Smev3TypesBasic);

						if (string.IsNullOrEmpty(prefixForSerialize) || string.Compare(prefixForSerialize, "xmlns", true) == 0)
						{
							prefixForSerialize = "";
						}

						log.LogDebug($"Полученное значение prefixForSerialize: {prefixForSerialize}.");

						log.LogDebug($"Пытаемся обновить список вложений.");
						XmlElement attachmentHeaderListNew = this.SerializeToXmlElement(headerList, NamespaceUri.Smev3TypesBasic, prefixForSerialize);
						attachmentHeaderListNew = doc.ImportNode(attachmentHeaderListNew, true) as XmlElement;
						attachmentHeaderList.ParentNode.ReplaceChild(attachmentHeaderListNew, attachmentHeaderList);
					}
				}
			}

			return doc;
		}

		/// <summary>
		/// 
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
		/// 
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="signedXml"></param>
		/// <param name="customTag"></param>
		/// <param name="customNamespace"></param>
		/// <param name="precedingSibling"></param>
		/// <returns></returns>
		private SignedXml AddReference(XmlDocument doc, SignedXml signedXml, IntPtr certificate, string customTag = "", string customNamespace = "", bool precedingSibling = false)
		{
			Reference reference = new Reference();
			string id = string.Empty;

			if (precedingSibling == false)
			{
				if (ElemForSign == SignedTag.CustomTag && string.IsNullOrEmpty(customTag) != true)
				{
					id = GetElemId(doc, customTag, customNamespace);

					if (string.IsNullOrEmpty(id) && SignWithId)
					{
						SetElemId(doc, customTag, NamespaceUri.WSSoap11);
					}
				}
				else
				{
					id = GetElemId(doc, tagForSign, tagForSignNamespaceUri);

					if (string.IsNullOrEmpty(id) && SignWithId)
					{
						id = SetElemId(doc, tagForSign, tagForSignNamespaceUri);
					}
				}
			}

			if (SignWithId)
			{
				reference.Uri = id;
			}
			else
			{
				reference.Uri = string.Empty;
			}

			log.LogDebug($"Пытаемся получить значение DigestMethod.");
			reference.DigestMethod = SignServiceUtils.GetDigestMethod(SignServiceUtils.GetAlgId(certificate));
			log.LogDebug($"Значение DigestMethod успешно получено: {reference.DigestMethod}.");

			if (string.IsNullOrEmpty(customTag) != true && ElemForSign == SignedTag.CustomTag)
			{
				XmlDsigEnvelopedSignatureTransform envelop = new XmlDsigEnvelopedSignatureTransform();
				reference.AddTransform(envelop);
			}

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			//if (MrVersion == Mr.MR300)
			//{
				SmevTransformAlg smevTransform = new SmevTransformAlg();
				reference.AddTransform(smevTransform);
			//}

			signedXml.AddReference(reference);

			return signedXml;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="elemName"></param>
		/// <param name="namespaceUri"></param>
		/// <param name="specId"></param>
		/// <returns></returns>
		private string SetElemId(XmlDocument doc, string elemName, string namespaceUri, string specId = "")
		{
			string newId = string.Empty;
			string existId = GetElemId(doc, elemName, namespaceUri);

			if (string.IsNullOrEmpty(existId) && this.SignWithId)
			{
				string lowerName = elemName.ToLower();
				XmlElement targetElem = (XmlElement)doc.GetElementsByTagName(elemName, namespaceUri)[0] ??
										(XmlElement)doc.GetElementsByTagName(lowerName, namespaceUri)[0];

				if (string.IsNullOrEmpty(specId))
				{
					newId = idCounter.ToString(CultureInfo.InvariantCulture);
					idCounter++;
				}
				else
				{
					newId = specId;
				}

				//if (this.MrVersion == Mr.MR300)
				//{
					XmlAttribute idAttr = doc.CreateAttribute("Id");
					idAttr.Value = newId;
					targetElem.Attributes.Append((XmlAttribute)doc.ImportNode(idAttr, true));
				//}
				//else
				//{
				//	XmlAttribute idAttr = doc.CreateAttribute("u", "Id", securityNamespace);
				//	idAttr.Value = newId;
				//	targetElem.Attributes.Append((XmlAttribute)doc.ImportNode(idAttr, true));
				//}
			}

			return newId;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="elemName"></param>
		/// <param name="namespaceUri"></param>
		/// <returns></returns>
		private string GetElemId(XmlDocument doc, string elemName, string namespaceUri)
		{
			string id = "";
			string lowerName = elemName.ToLower();

			if (SignWithId)
			{
				XmlElement targetElem = (XmlElement)doc.GetElementsByTagName(elemName, namespaceUri)[0] ??
										(XmlElement)doc.GetElementsByTagName(lowerName, namespaceUri)[0];

				if (targetElem.HasAttribute("Id"))
				{
					id += "#" + targetElem.GetAttribute("Id");
				}
				else if (targetElem.HasAttribute("Id", securityNamespace))
				{
					id += "#" + targetElem.GetAttribute("Id", securityNamespace);
				}
				else if (targetElem.HasAttribute("id", securityNamespace))
				{
					id += "#" + targetElem.GetAttribute("id", securityNamespace);
				}
			}
			else
			{
				id = "";
			}

			return id;
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
			RemoveNodes(node, nodeList);
		}

		/// <summary>
		/// Удаление списка элементов.
		/// </summary>
		/// <param name="node">Откуда удалить.</param>
		/// <param name="nodeList">Список элементов, которые надо удалить.</param>
		private void RemoveNodes(XmlElement node, XmlNodeList nodeList)
		{
			if (nodeList != null && nodeList.Count > 0)
			{
				for (int i = nodeList.Count - 1; i >= 0; i--)
				{
					nodeList[i].ParentNode.RemoveChild(nodeList[i]);
				}
			}
		}

		/// <summary>
		/// 
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
		/// 
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
			wrapper = (T)ser.Deserialize(new StringReader(toDeserialize));

			return wrapper;
		}
	}
}
