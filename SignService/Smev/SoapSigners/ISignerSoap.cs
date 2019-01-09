using System;
using System.Xml;

namespace SignService.Smev.SoapSigners
{
	internal interface ISignerSoap
	{
		XmlDocument SignMessageAsOv(XmlDocument doc, IntPtr certificate, string password);

		SignedTag ElemForSign { get; set; }
		bool SignWithId { get; set; }
	}
}
