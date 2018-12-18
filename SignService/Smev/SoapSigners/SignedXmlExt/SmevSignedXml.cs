using SignService.CommonUtils;
using SignService.Smev.Utils;
using SignService.Unix.Gost;
using SignService.Unix.Utils;
using SignService.Win.Gost;
using SignService.Win.Utils;
using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignService.Smev.SoapSigners.SignedXmlExt
{
	/// <summary>
	/// Класс для подписи XML
	/// </summary>
	internal class SmevSignedXml : SignedXml
	{
		public SmevSignedXml()
		{
			this.NamespaceForReference = NamespaceUri.OasisWSSecurityUtility;
		}

		public SmevSignedXml(XmlDocument document)
			: base(document)
		{
			this.NamespaceForReference = NamespaceUri.OasisWSSecurityUtility;
		}

		public string NamespaceForReference { get; set; }

		/// <summary>
		/// 
		/// </summary>
		/// <param name="document"></param>
		/// <param name="idValue"></param>
		/// <returns></returns>
		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			XmlNamespaceManager nsmgr = new XmlNamespaceManager(document.NameTable);
			XmlElement element = null;

			if (string.IsNullOrEmpty(idValue) == false)
			{
				string prefix = SoapDSigUtil.FindPrefix(document.DocumentElement, this.NamespaceForReference);

				if (string.IsNullOrEmpty(prefix))
				{
					prefix = "wsu";
				}

				nsmgr.AddNamespace(prefix, this.NamespaceForReference);

				string findString = string.Format("//*[(@Id='{0}' and namespace-uri()='{1}') or (@{2}:Id='{0}')]", idValue, this.NamespaceForReference, prefix);
				element = document.SelectSingleNode(findString, nsmgr) as XmlElement;
			}
			else if (document.DocumentElement != null)
			{
				element = document.DocumentElement;
			}

			return element;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prefix"></param>
		public void ComputeSignature(string prefix)
		{
			this.BuildDigestedReferences();
			SignatureDescription description = CryptoConfig.CreateFromName(this.SignedInfo.SignatureMethod) as SignatureDescription;
			HashAlgorithm hash = description.CreateDigest();

			GetDigest(hash, prefix);
			this.m_signature.SignatureValue = description.CreateFormatter(this.SigningKey).CreateSignature(hash);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prefix"></param>
		/// <param name="certificate"></param>
		public void ComputeSignatureWithoutPrivateKey(string prefix, IntPtr certificate)
		{
			if (SignServiceUtils.IsUnix)
			{
				CryptoConfig.AddAlgorithm(typeof(Gost2001Unix), new string[1] { "http://www.w3.org/2001/04/xmldsig-more#gostr3411" });
				CryptoConfig.AddAlgorithm(typeof(Gost2012_256Unix), new string[1] { "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256" });
			}
			else
			{
				CryptoConfig.AddAlgorithm(typeof(Gost2001), new string[1] { "http://www.w3.org/2001/04/xmldsig-more#gostr3411" });
				CryptoConfig.AddAlgorithm(typeof(Gost2012_256), new string[1] { "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256" });
			}

			BuildDigestedReferences();

			int algId = 0;
			HashAlgorithm hash = SignServiceUtils.GetHashAlgObject(certificate, ref algId);
			GetDigest(hash, prefix);

			uint keySpec = CApiExtConst.AT_SIGNATURE;
			IntPtr cpHandle = (SignServiceUtils.IsUnix) ? UnixExtUtil.GetHandler(certificate, out keySpec) : Win32ExtUtil.GetHandler(certificate, out keySpec);

			byte[] sign = (SignServiceUtils.IsUnix) ? UnixExtUtil.SignValue(cpHandle, (int)keySpec, hash.Hash, (int)0, algId) :
				Win32ExtUtil.SignValue(cpHandle, (int)keySpec, hash.Hash, (int)0, algId);

			Array.Reverse(sign);
			m_signature.SignatureValue = sign;

			SignServiceUtils.ReleaseProvHandle(cpHandle);
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
		/// <param name="hash"></param>
		/// <param name="prefix"></param>
		private void GetDigest(HashAlgorithm hash, string prefix)
		{
			XmlDocument document = new XmlDocument { PreserveWhitespace = true };

			XmlElement e = this.SignedInfo.GetXml();
			document.AppendChild(document.ImportNode(e, true));

			Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
			SetPrefix(prefix, document);

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
	}
}
