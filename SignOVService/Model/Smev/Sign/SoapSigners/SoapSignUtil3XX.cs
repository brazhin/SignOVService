using Microsoft.Extensions.Logging;
using SignOVService.Model.Cryptography;
using SignOVService.Model.Smev.Model;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Serialization;

namespace SignOVService.Model.Smev.Sign.SoapSigners
{
	public class SoapSignUtil3XX : ISoapSigner
	{
		private const string XmlDsigGost3410UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
		private const string XmlDsigGost3411UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
		private const string XmlDsigSha1UrlObsolete = "http://www.w3.org/2000/09/xmldsig#sha1";
		private const string xmldsigPrefix = "ds";

		private readonly string mrNamespace;
		private readonly string securityNamespace;
		private string tagForSign;

		public SoapSignUtil3XX(MR mr)
		{
			MrVersion = mr;
			SignWithId = false;
			ElemForSign = SignedTag.Body;

			if (MrVersion != MR.MR300)
			{
				throw new NotImplementedException("Неподдерживаемая версия методических рекомендаций");
			}

			mrNamespace = NamespaceUri.SmevMR300;
			securityNamespace = NamespaceUri.Smev3Types;
			tagForSign = string.Empty;
		}

		public SignedTag ElemForSign { get; set; }
		public bool SignWithId { get; set; }
		public MR MrVersion { get; }

		public XmlDocument SignMessageAsOv(XmlDocument doc, X509Certificate2 certificate)
		{
			if (MrVersion != MR.MR300)
			{
				throw new NotImplementedException("Неподдерживаемая версия методических рекомендаций.");
			}

			return SignMessage3XX(doc, certificate);
		}

		public XmlDocument SignMessageAsSP(XmlDocument indoc, X509Certificate2 certificate, string tag, string namespaceUri, bool fillInTheEnd)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Метод подписания
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		private XmlDocument SignMessage3XX(XmlDocument doc, X509Certificate2 certificate)
		{
			try
			{
				// Подписываем вложения
				doc = SignAttachmentsOv(doc, certificate);
				doc.Save("signed.xml");
			}
			catch (Exception ex)
			{
				throw new Exception("Ошибка при попытке проверить и подписать вложения", ex);
			}

			ElemForSign = SignedTag.Smev3TagType;
			tagForSign = FindSmevTagForSign(doc);

			return doc;
		}

		/// <summary>
		/// Метод подписания вложений подписью органа власти
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		private XmlDocument SignAttachmentsOv(XmlDocument doc, X509Certificate2 certificate)
		{
			XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);

			string prefix = SoapDSigUtil.FindPrefix(doc.DocumentElement, NamespaceUri.Smev3TypesBasic);

			if (string.IsNullOrEmpty(prefix) || string.Compare(prefix, "xmlns", true) == 0)
			{
				prefix = "typesBasic";
			}

			nsmgr.AddNamespace(prefix, NamespaceUri.Smev3TypesBasic);

			string findHeaderString = string.Format("//{0}:AttachmentHeaderList", prefix);
			XmlElement attachmentHeaderList = doc.SelectSingleNode(findHeaderString, nsmgr) as XmlElement;

			string findContentString = string.Format("//{0}:AttachmentContentList", prefix);
			XmlElement attachmentContentList = doc.SelectSingleNode(findContentString, nsmgr) as XmlElement;

			if (attachmentHeaderList != null && attachmentContentList != null)
			{
				bool changed = false;
				SignatureCryptography signatureCryptography = new SignatureCryptography();
				AttachmentHeaderList headerList = DeserializeXml<AttachmentHeaderList>(attachmentHeaderList, NamespaceUri.Smev3TypesBasic);
				AttachmentContentList contentList = DeserializeXml<AttachmentContentList>(attachmentContentList, NamespaceUri.Smev3TypesBasic);

				if (headerList != null && headerList.AttachmentHeader != null && headerList.AttachmentHeader.Length > 0
					&& contentList != null && contentList.AttachmentContent != null && contentList.AttachmentContent.Length > 0)
				{
					foreach (AttachmentHeaderType header in headerList.AttachmentHeader)
					{
						if (header.SignaturePKCS7 == null || header.SignaturePKCS7.Length == 0)
						{
							AttachmentContentType content = contentList.AttachmentContent.FirstOrDefault(cnt => cnt.Id == header.contentId);

							if (content != null && content.Content != null && content.Content.Length > 0)
							{
								byte[] signature = signatureCryptography.SignWithCertificate(new MemoryStream(content.Content), certificate);
								header.SignaturePKCS7 = signature;
								changed = true;
							}
						}
					}

					if (changed)
					{
						string prefixForSerialize = SoapDSigUtil.FindPrefix(doc.DocumentElement, NamespaceUri.Smev3TypesBasic);

						if (string.IsNullOrEmpty(prefixForSerialize) || string.Compare(prefixForSerialize, "xmlns", true) == 0)
						{
							prefixForSerialize = "";
						}

						XmlElement attachmentHeaderListNew = this.SerializeToXmlElement(headerList, NamespaceUri.Smev3TypesBasic, prefixForSerialize);
						attachmentHeaderListNew = doc.ImportNode(attachmentHeaderListNew, true) as XmlElement;
						attachmentHeaderList.ParentNode.ReplaceChild(attachmentHeaderListNew, attachmentHeaderList);
					}
				}
			}

			return doc;
		}

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

		/// <summary>
		/// Метод поиска тэга в который необходимо добавить подпись
		/// </summary>
		/// <param name="doc"></param>
		/// <returns></returns>
		private string FindSmevTagForSign(XmlDocument doc)
		{
			string result = string.Empty;

			//if (MrVersion == MR.MR300)
			//{
			//	this.tagForSignNamespaceUri = NamespaceUri.Smev3Types;
			//	string[] tagNames = SmevMr3xxTags.GetAllRequestTags();

			//	string baseTagName = string.Empty;
			//	XmlElement basetElem = null;

			//	if (tagNames != null)
			//	{
			//		for (int elemCounter = 0; (elemCounter < tagNames.Length) && (string.IsNullOrEmpty(baseTagName)); elemCounter++)
			//		{
			//			string elemName = tagNames[elemCounter];
			//			string lowerName = elemName.ToLower();

			//			this.tagForSignNamespaceUri = SmevMr3xxTags.GetNamespaceTagByTag(elemName);

			//			basetElem = (XmlElement)doc.GetElementsByTagName(elemName, this.tagForSignNamespaceUri)[0] ??
			//						 (XmlElement)doc.GetElementsByTagName(lowerName, this.tagForSignNamespaceUri)[0];
			//			if (basetElem != null)
			//			{
			//				baseTagName = elemName;
			//			}
			//		}
			//	}

			//	this.tagForRequest = baseTagName;
			//	this.tagForRequestNamespaceUri = this.tagForSignNamespaceUri;
			//	this.tagForSignNamespaceUri = NamespaceUri.Smev3TypesBasic;
			//	tagNames = SmevMr3xxTags.GetSignTagByRequestTag(baseTagName);

			//	XmlElement targetElem = null;

			//	if (tagNames != null)
			//	{
			//		for (int elemCounter = 0; (elemCounter < tagNames.Length) && (string.IsNullOrEmpty(result)); elemCounter++)
			//		{
			//			string elemName = tagNames[elemCounter];
			//			string lowerName = elemName.ToLower();

			//			this.tagForSignNamespaceUri = SmevMr3xxTags.GetNamespaceTagByTag(elemName);

			//			targetElem = (XmlElement)doc.GetElementsByTagName(elemName, this.tagForSignNamespaceUri)[0] ??
			//						 (XmlElement)doc.GetElementsByTagName(lowerName, this.tagForSignNamespaceUri)[0];
			//			if (targetElem != null)
			//			{
			//				result = elemName;
			//			}
			//		}
			//	}
			//}

			return result;
		}
	}
}
