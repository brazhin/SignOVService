using System.Diagnostics;

namespace SignOVService.Model.Smev.Sign.SmevTransform
{
	/// <summary>
	/// 
	/// </summary>
	[DebuggerDisplay("{Prefix}:{LocalName}={Value}[{NamespaceURI}]")]
	internal class XmlAttributeWrap
	{
		public XmlAttributeWrap()
		{
		}

		public XmlAttributeWrap(string prefix, string localName, string namespaceURI, string value)
		{
			LocalName = localName;
			NamespaceURI = namespaceURI;
			Prefix = prefix;
			Value = value;
		}

		/// <summary>
		/// 
		/// </summary>
		public string LocalName { get; set; }

		/// <summary>
		/// 
		/// </summary>
		public string NamespaceURI { get; set; }

		/// <summary>
		/// 
		/// </summary>
		public string Prefix { get; set; }

		/// <summary>
		/// 
		/// </summary>
		public string Value { get; set; }
	}
}
