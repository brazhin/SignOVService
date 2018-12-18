using SignService.Smev.SoapSigners.SignedXmlExt;
using System;
using System.Xml;

namespace SignService.Smev.Utils
{
	internal class SoapDSigUtil
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="elem"></param>
		/// <param name="namespaceURI"></param>
		/// <returns></returns>
		internal static string FindPrefix(XmlElement elem, string namespaceURI)
		{
			string result = string.Empty;

			if (string.Compare(elem.NamespaceURI, namespaceURI, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = elem.Prefix;
			}

			if (string.IsNullOrEmpty(result))
			{
				foreach (XmlAttribute att in elem.Attributes)
				{
					if (string.Compare(att.Value, namespaceURI, StringComparison.InvariantCultureIgnoreCase) == 0)
					{
						result = att.LocalName;
						break;
					}
				}
			}

			if (string.IsNullOrEmpty(result))
			{
				foreach (XmlNode node in elem.ChildNodes)
				{
					XmlElement chElem = node as XmlElement;
					if (chElem != null)
					{
						result = FindPrefix(chElem, namespaceURI);
					}
					if (string.IsNullOrEmpty(result) == false)
					{
						break;
					}
				}
			}

			return result;
		}

		/// <summary>
		/// Метод удаления тэга Actor из XML СМЭВ2
		/// </summary>
		/// <param name="xmlDocument"></param>
		/// <returns></returns>
		internal static string RemoveActor(XmlDocument xmlDocument)
		{
			string message = xmlDocument.OuterXml;
			XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("Envelope", NamespaceUri.WSSoap11);
			if (elementsByTagName.Count != 0)
			{
				string prefixOfNamespace = elementsByTagName[0].GetPrefixOfNamespace(NamespaceUri.WSSoap11);
				if (!string.IsNullOrEmpty(prefixOfNamespace))
				{
					message = message.Replace(string.Concat(prefixOfNamespace, ":actor=\"", SmevAttributes.ActorRecipient, "\""), "");
					message = message.Replace(string.Concat(prefixOfNamespace, ":actor=\"", SmevAttributes.ActorSmev, "\""), "");
				}
				else
				{
					throw new XmlException(string.Format("Не найден префикс пространста имен {0}", NamespaceUri.WSSoap11));
				}
			}
			else
			{
				throw new XmlException("Не найден узел Envelope");
			}

			return message;
		}

		/// <summary>
		/// Метод добавления тэга Actor в XML СМЭВ2
		/// </summary>
		/// <param name="xmlDocument"></param>
		internal static void AddActor(XmlDocument xmlDocument)
		{
			var prefixOfNamespace = xmlDocument.DocumentElement.GetPrefixOfNamespace(NamespaceUri.WSSoap11);
			if (string.IsNullOrEmpty(prefixOfNamespace))
				throw new XmlException(string.Format("Не найден префикс пространста имен {0}", NamespaceUri.WSSoap11));

			var elementsByTagName = xmlDocument.GetElementsByTagName("Security", NamespaceUri.OasisWSSecuritySecext);
			if (elementsByTagName.Count == 0)
				throw new NullReferenceException("Не найден подпись под документом.");

			var attribute = xmlDocument.CreateAttribute(prefixOfNamespace + ":actor", NamespaceUri.WSSoap11);
			attribute.Value = SmevAttributes.ActorSmev;
			var xmlAttributeCollection = elementsByTagName[0].Attributes;
			if (xmlAttributeCollection != null)
			{
				xmlAttributeCollection.Append(attribute);
			}
		}
	}
}
