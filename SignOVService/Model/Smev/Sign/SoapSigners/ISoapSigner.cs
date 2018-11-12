using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model.Smev.Sign.SoapSigners
{
	public interface ISoapSigner
	{
		SignedTag ElemForSign { get; set; }
		bool SignWithId { get; set; }
		XmlDocument SignMessageAsOv(XmlDocument doc, X509Certificate2 certificate);
		XmlDocument SignMessageAsSP(XmlDocument indoc, X509Certificate2 certificate, string tag, string namespaceUri, bool fillInTheEnd);
	}
}
