using SignService.CommonUtils;
using SignService.Smev.SmevTransform;
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
	internal class Smev3xxSignedXml : SignedXml
	{
		private XmlElement containingDocument;

		internal Smev3xxSignedXml()
		{

		}

		internal Smev3xxSignedXml(XmlDocument document) :
			base(document)
		{
			containingDocument = document.DocumentElement;
		}

		/// <summary>
		/// Метод вычисления подписи без использования закрытого ключа
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

			CryptoConfig.AddAlgorithm(typeof(SmevTransformAlg), new string[1] { SmevTransformAlg.ALGORITHM_URI });

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
		/// <param name="prefix"></param>
		/// <returns></returns>
		internal XmlElement GetXml(string prefix)
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

		/// <summary>
		/// 
		/// </summary>
		private void BuildDigestedReferences()
		{
			Type t = typeof(SignedXml);
			MethodInfo m = t.GetMethod("BuildDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance);
			m.Invoke(this, new object[] { });
		}
	}
}
