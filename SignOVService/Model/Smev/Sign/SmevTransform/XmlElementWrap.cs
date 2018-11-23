namespace SignOVService.Model.Smev.Sign.SmevTransform
{
	/// <summary>
	/// 
	/// </summary>
	internal class XmlElementWrap
	{
		public XmlElementWrap(string prefix, string localName, string namespaceURI)
		{
			LocalName = localName;
			NamespaceURI = namespaceURI;
			Prefix = prefix;
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
	}
}
