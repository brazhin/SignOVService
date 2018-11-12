using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model.Smev.Sign
{
	public class SignSoapImpl
	{
		private readonly ILogger<SignSoapImpl> log;
		private readonly SoapSignUtil senderSignUtil;

		public SignSoapImpl(X509Certificate2 currentCertificate, MR mR)
		{
			this.Certificate = currentCertificate;
			this.senderSignUtil = new SoapSignUtil(Certificate, mR);
		}

		public X509Certificate2 Certificate { get; }

		/// <summary>
		/// Метод подписания, модифицирует xml перед подписанием и после подписания в случае если версия мр == 244 или 255
		/// </summary>
		/// <param name="soap"></param>
		/// <returns></returns>
		public XmlDocument SignSoapOV(XmlDocument soap)
		{
			string message = soap.OuterXml;

			if (senderSignUtil.MrVersion == MR.MR244 || senderSignUtil.MrVersion == MR.MR255)
			{
				message = SoapDSigUtil.RemoveActor(soap);
			}

			XmlDocument doc = new XmlDocument { PreserveWhitespace = true };
			doc.LoadXml(message);

			senderSignUtil.ElemForSign = SignedTag.Body;
			senderSignUtil.SignWithId = true;

			doc = senderSignUtil.SignMessage(doc);

			if (senderSignUtil.MrVersion == MR.MR244 || senderSignUtil.MrVersion == MR.MR255)
			{
				SoapDSigUtil.AddActor(doc);
			}

			return doc;
		}
	}
}
