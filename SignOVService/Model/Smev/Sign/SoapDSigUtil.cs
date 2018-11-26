using System;
using System.Xml;

namespace SignOVService.Model.Smev.Sign
{
	/// <summary>
	/// 
	/// </summary>
	public class SoapDSigUtil
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="elem"></param>
		/// <param name="namespaceURI"></param>
		/// <returns></returns>
		public static string FindPrefix(XmlElement elem, string namespaceURI)
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
		/// 
		/// </summary>
		/// <param name="xmlDocument"></param>
		/// <returns></returns>
		public static string RemoveActor(XmlDocument xmlDocument)
		{
			return "";
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="xmlDocument"></param>
		public static void AddActor(XmlDocument xmlDocument)
		{
		}
	}
}
