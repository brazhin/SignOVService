using SignService.CommonUtils;
using SignService.Smev.SmevTransform;
using SignService.Smev.SoapSigners;
using SignService.Smev.SoapSigners.SignedXmlExt;
using System;
using System.Globalization;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignService.Smev.Utils
{
	/// <summary>
	/// Класс обертка для методов используемых в классах SignerXml2XX/SignerXml3XX
	/// </summary>
	internal static class SmevXmlHelper
	{

		/// <summary>
		/// Метод добавляет в XML тэг <ds:Reference></Reference>
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="signedXml"></param>
		/// <param name="customTag"></param>
		/// <param name="customNamespace"></param>
		/// <param name="precedingSibling"></param>
		/// <returns></returns>
		internal static SignedXml AddReference(XmlDocument doc, SignedXml signedXml, IntPtr certificate, bool signWithId, Mr mr,
			SignedTag elemForSign,
			ref int idCounter,
			string tagForSign,
			string tagForSignNamespaceUri,
			string namespaceIdAttr = "",
			string customTag = "", 
			string customNamespace = ""
		)
		{
			Reference reference = new Reference();
			string id = string.Empty;

			if (elemForSign == SignedTag.CustomTag && string.IsNullOrEmpty(customTag) != true)
			{
				id = SmevXmlHelper.GetElemId(doc, customTag, customNamespace, signWithId);

				if (string.IsNullOrEmpty(id) && signWithId)
				{
					if(mr == Mr.MR300)
						SmevXmlHelper.SetElemId(doc, customTag, NamespaceUri.WSSoap11, signWithId, mr, ref idCounter);
					else
						id = "#" + SmevXmlHelper.SetElemId(doc, customTag, tagForSignNamespaceUri, signWithId, mr, ref idCounter, "", namespaceIdAttr);
				}
			}
			else
			{
				id = SmevXmlHelper.GetElemId(doc, tagForSign, tagForSignNamespaceUri, signWithId);

				if (string.IsNullOrEmpty(id) && signWithId)
				{
					if (mr == Mr.MR300)
						id = SmevXmlHelper.SetElemId(doc, tagForSign, tagForSignNamespaceUri, signWithId, mr, ref idCounter);
					else
						id = "#" + SmevXmlHelper.SetElemId(doc, tagForSign, tagForSignNamespaceUri, signWithId, mr, ref idCounter, "", namespaceIdAttr);
				}
			}

			reference.Uri = (signWithId) ? id : string.Empty;
			reference.DigestMethod = SignServiceUtils.GetDigestMethod(SignServiceUtils.GetAlgId(certificate));

			if (string.IsNullOrEmpty(customTag) != true && elemForSign == SignedTag.CustomTag)
			{
				XmlDsigEnvelopedSignatureTransform envelop = new XmlDsigEnvelopedSignatureTransform();
				reference.AddTransform(envelop);
			}

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			if (mr == Mr.MR300)
			{
				SmevTransformAlg smevTransform = new SmevTransformAlg();
				reference.AddTransform(smevTransform);
			}

			signedXml.AddReference(reference);

			return signedXml;
		}

		/// <summary>
		/// Устанавливает значение для тэга с идентификатором, влияет на установку <ds:Reference URI=></Reference>
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="elemName"></param>
		/// <param name="namespaceUri"></param>
		/// <param name="signWithId"></param>
		/// <param name="specId"></param>
		/// <param name="namespaceIdAttr"></param>
		/// <returns></returns>
		internal static string SetElemId(XmlDocument doc, string elemName, string namespaceUri, bool signWithId, 
			Mr mr,
			ref int idCounter,
			string specId = "", 
			string namespaceIdAttr = ""
		)
		{
			string newId = string.Empty;
			string existId = GetElemId(doc, elemName, namespaceUri, signWithId);

			if (string.IsNullOrEmpty(existId) && signWithId)
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

				if (mr == Mr.MR300)
				{
					XmlAttribute idAttr = doc.CreateAttribute("Id");
					idAttr.Value = newId;
					targetElem.Attributes.Append((XmlAttribute)doc.ImportNode(idAttr, true));
				}
				else
				{
					XmlAttribute idAttr = doc.CreateAttribute("u", "Id", namespaceIdAttr);
					idAttr.Value = newId;
					targetElem.Attributes.Append((XmlAttribute)doc.ImportNode(idAttr, true));
				}
			}

			return newId;
		}

		/// <summary>
		/// Метод получает тэг по идентификатору, влияет на установку <ds:Reference URI=></Reference>
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="elemName"></param>
		/// <param name="namespaceUri"></param>
		/// <param name="namespaceIdAttr"></param>
		/// <returns></returns>
		internal static string GetElemId(XmlDocument doc, string elemName, string namespaceUri, bool signWithId, string namespaceIdAttr = "")
		{
			string id = string.Empty;
			string lowerName = elemName.ToLower();

			if (signWithId)
			{
				XmlElement targetElem = (XmlElement)doc.GetElementsByTagName(elemName, namespaceUri)[0] ??
					(XmlElement)doc.GetElementsByTagName(lowerName, namespaceUri)[0];

				if (targetElem.HasAttribute("Id"))
				{
					id += "#" + targetElem.GetAttribute("Id");
				}
				else if (targetElem.HasAttribute("Id", namespaceIdAttr))
				{
					id += "#" + targetElem.GetAttribute("Id", namespaceIdAttr);
				}
				else if (targetElem.HasAttribute("id", namespaceIdAttr))
				{
					id += "#" + targetElem.GetAttribute("id", namespaceIdAttr);
				}
			}

			return id;
		}

		/// <summary>
		/// Удаление списка элементов.
		/// </summary>
		/// <param name="node">Откуда удалить.</param>
		/// <param name="nodeList">Список элементов, которые надо удалить.</param>
		internal static void RemoveNodes(XmlElement node, XmlNodeList nodeList)
		{
			if (nodeList != null && nodeList.Count > 0)
			{
				for (int i = nodeList.Count - 1; i >= 0; i--)
				{
					nodeList[i].ParentNode.RemoveChild(nodeList[i]);
				}
			}
		}
	}
}
