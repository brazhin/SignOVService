using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignOVService.Model.Smev.Sign
{
	/// <summary>
	/// 
	/// </summary>
	public class Smev3xxSignedXml : SignedXml
	{
		/// <summary>
		/// 
		/// </summary>
		private XmlElement containingDocument;

		public Smev3xxSignedXml()
		{

		}

		public Smev3xxSignedXml(XmlDocument document)
		{
			containingDocument = document.DocumentElement;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prefix"></param>
		/// <param name="certificate"></param>
		public void ComputeSignatureWithoutPrivateKey(string prefix, X509Certificate2 certificate)
		{

		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="document"></param>
		/// <param name="idValue"></param>
		/// <returns></returns>
		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			XmlNamespaceManager nsmgr = new XmlNamespaceManager(document.NameTable);
			nsmgr.AddNamespace("smev3", NamespaceUri.Smev3Types);
			XmlElement result = document.SelectSingleNode("//*[@smev3:Id='" + idValue + "']", nsmgr) as XmlElement;

			if (result == null)
			{
				XmlNamespaceManager nsmgr2 = new XmlNamespaceManager(document.NameTable);
				nsmgr2.AddNamespace("smev3", NamespaceUri.Smev3TypesBasic);
				result = document.SelectSingleNode("//*[@smev3:Id='" + idValue + "']", nsmgr2) as XmlElement;
			}

			if (result == null)
			{
				result = document.SelectSingleNode("//*[@Id='" + idValue + "']", nsmgr) as XmlElement;
			}

			return result;
		}

		/// <summary>
		/// 
		/// </summary>
		private void BuildDigestedReferences()
		{
			Type t = typeof(SignedXml);
			MethodInfo m = t.GetMethod("BuildDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance);
			m.Invoke(this, new object[] { });
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prefix"></param>
		/// <returns></returns>
		public XmlElement GetXml(string prefix)
		{
			XmlElement e = this.GetXml();
			SetPrefix(prefix, e);
			return e;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hash"></param>
		/// <param name="prefix"></param>
		private void GetDigest(HashAlgorithm hash, string prefix)
		{
			XmlDocument document = new XmlDocument { PreserveWhitespace = true };

			XmlElement e = this.SignedInfo.GetXml();
			document.AppendChild(document.ImportNode(e, true));

			Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
			this.SetPrefix(prefix, document);

			canonicalizationMethodObject.LoadInput(document);
			canonicalizationMethodObject.GetDigestedOutput(hash);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prefix"></param>
		/// <param name="parent"></param>
		private void SetPrefix(string prefix, XmlNode parent)
		{
			foreach (XmlNode node in parent.ChildNodes)
				SetPrefix(prefix, node);
			parent.Prefix = prefix;
		}
	}
}
