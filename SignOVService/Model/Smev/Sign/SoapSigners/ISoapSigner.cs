using SignOVService.Model.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model.Smev.Sign.SoapSigners
{
	public interface ISoapSigner
	{
		XmlDocument SignMessageAsOv(XmlDocument doc, /*X509Certificate2*/X509Certificate2Custom certificate);
		//XmlDocument SignMessageAsSP(XmlDocument indoc, X509Certificate2 certificate, string tag, string namespaceUri, bool fillInTheEnd);

		SignedTag ElemForSign { get; set; }
		bool SignWithId { get; set; }
	}
}
