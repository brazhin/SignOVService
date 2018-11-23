using System;
using System.Collections.Generic;
using System.Linq;

namespace SignOVService.Model.Smev.Sign.SmevTransform
{
	/// <summary>
	/// 
	/// </summary>
	internal class AttributeSortingComparer : IComparer<XmlAttributeWrap>
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="x"></param>
		/// <param name="y"></param>
		/// <returns></returns>
		public int Compare(XmlAttributeWrap x, XmlAttributeWrap y)
		{
			string xNS = x.NamespaceURI;
			string xLocal = x.LocalName;
			string xPrefix = x.Prefix;
			string yNS = y.NamespaceURI;
			string yLocal = y.LocalName;
			string yPrefix = y.Prefix;

			// Сначала сравниваем namespaces.
			if (xNS == null || xNS.Equals(""))
			{
				if (yNS != null && !"".Equals(yNS))
				{
					return -1;
				}
			}
			else
			{
				if (yNS == null || "".Equals(yNS))
				{
					return 1;
				}
				else
				{

					if (xPrefix.Equals("xmlns", StringComparison.InvariantCultureIgnoreCase))
					{
						if (yPrefix.Equals("xmlns", StringComparison.InvariantCultureIgnoreCase) == false)
						{
							return -1;
						}
					}
					else
					{
						if (yPrefix.Equals("xmlns", StringComparison.InvariantCultureIgnoreCase))
						{
							return 1;
						}
						else
						{
							if (string.IsNullOrEmpty(xPrefix))
							{
								if (string.IsNullOrEmpty(yPrefix) == false)
								{
									return 1;
								}
							}
							else
							{
								if (string.IsNullOrEmpty(yPrefix))
								{
									return -1;
								}
								else
								{
									//int nsComparisonResult = xPrefix.CompareTo(yPrefix);
									int nsComparisonResult = string.Compare(xNS, yNS, StringComparison.Ordinal);
									//int nsComparisonResult = xNS.CompareTo(yNS);
									if (nsComparisonResult != 0)
									{
										return nsComparisonResult;
									}
								}
							}
						}
					}
				}
			}

			//// Если namespaces признаны эквивалентными, сравниваем local names.
			return string.Compare(xLocal, yLocal, StringComparison.Ordinal);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="attributes"></param>
		/// <param name="elementPrefix"></param>
		/// <returns></returns>
		public List<XmlAttributeWrap> SortXmlns(List<XmlAttributeWrap> attributes, string elementPrefix)
		{
			List<XmlAttributeWrap> result = new List<XmlAttributeWrap>();
			XmlAttributeWrap elementNamespace = null;
			List<XmlAttributeWrap> attributesValue = new List<XmlAttributeWrap>();
			List<XmlAttributeWrap> attributesNamespace = new List<XmlAttributeWrap>();

			foreach (XmlAttributeWrap tmpAtt in attributes)
			{
				if (string.Compare(tmpAtt.LocalName, elementPrefix, StringComparison.Ordinal) == 0)//IgnoreCase
				{
					elementNamespace = tmpAtt;
				}
				else if (string.Compare(tmpAtt.Prefix, "xmlns", StringComparison.InvariantCultureIgnoreCase) == 0)
				{
					attributesNamespace.Add(tmpAtt);
				}
				else
				{
					attributesValue.Add(tmpAtt);
				}
			}

			if (elementNamespace != null)
			{
				result.Add(elementNamespace);
			}

			foreach (XmlAttributeWrap tmpAtt in attributesValue)
			{
				XmlAttributeWrap attNamespace = attributesNamespace.FirstOrDefault(att => string.Compare(att.LocalName, tmpAtt.Prefix, StringComparison.InvariantCulture) == 0);//IgnoreCase
				if (attNamespace != null)
				{
					attributesNamespace.Remove(attNamespace);
					result.Add(attNamespace);

				}
			}

			foreach (XmlAttributeWrap tmpAtt in attributesValue)
			{
				result.Add(tmpAtt);
			}

			return result;
		}
	}
}
