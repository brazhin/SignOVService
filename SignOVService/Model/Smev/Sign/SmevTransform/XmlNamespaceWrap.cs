namespace SignOVService.Model.Smev.Sign.SmevTransform
{
	/// <summary>
	/// 
	/// </summary>
	internal class XmlNamespaceWrap
	{
		public XmlNamespaceWrap()
		{
			Added = true;
		}

		public XmlNamespaceWrap(string prefix, string namespaceURI)
		{
			Added = true;
			NamespaceURI = namespaceURI;
			Prefix = prefix;
		}

		/// <summary>
		/// 
		/// </summary>
		public bool Added { get; set; }

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
