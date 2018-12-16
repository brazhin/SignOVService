using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Smev.Utils;
using SignService.Smev.XmlSigners.SignedXmlExt;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignService.Smev.XmlSigners
{
	/// <summary>
	/// Реализация подписи XML для СМЭВ2
	/// </summary>
	internal class SignerXml2XX : ISignerXml
	{
		private const string xmldsigPrefix = "ds";

		private readonly Mr mrVersion;
		private readonly ILogger<SignerXml2XX> log;
		private string mrNamespace;
		private string securityNamespace = NamespaceUri.OasisWSSecurityUtility;

		private int idCounter = 1;
		private string tagForSign = string.Empty;
		private string tagForSignNamespaceUri = string.Empty;

		internal SignerXml2XX(Mr mr, ILoggerFactory loggerFactory)
		{
			this.SignWithId = false;
			this.ElemForSign = SignedTag.Body;
			this.mrVersion = mr;

			if (mr == Mr.MR244)
			{
				mrNamespace = NamespaceUri.SmevMR244;
				securityNamespace = NamespaceUri.OasisWSSecurityUtility;
			}
			else if(mr == Mr.MR255)
			{
				mrNamespace = NamespaceUri.SmevMR255;
				securityNamespace = NamespaceUri.OasisWSSecurityUtility;
			}
			else
			{
				throw new ArgumentException($"Неподдерживаемая версия МР: {mr}.");
			}

			this.log = loggerFactory.CreateLogger<SignerXml2XX>();
		}

		public SignedTag ElemForSign { get; set; }
		public bool SignWithId { get; set; }

		/// <summary>
		/// Метод подписи XML подписью органа власти
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		public XmlDocument SignMessageAsOv(XmlDocument doc, IntPtr certificate)
		{
			XmlDocument result = null;

			switch (this.mrVersion)
			{
				case Mr.MR244:
				case Mr.MR255:
					result = this.SignMessage2XX(doc, certificate);
					break;
				default:
					throw new NotImplementedException("Неподдерживаемая версия методических рекомендаций");
			}

			return result;
		}

		/// <summary>
		/// Метод подписи XML подписью органа власти
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="certificate"></param>
		/// <returns></returns>
		private XmlDocument SignMessage2XX(XmlDocument xml, IntPtr certificate)
		{
			// Удаляем тэг Actor
			var message = SoapDSigUtil.RemoveActor(xml);

			XmlDocument doc = new XmlDocument() { PreserveWhitespace = true };
			doc.LoadXml(message);

			this.tagForSign = this.FindSmevTagForSign(doc);
			SmevSignedXml signedXml = new SmevSignedXml(doc);

			signedXml = (SmevSignedXml)SmevXmlHelper.AddReference(doc, signedXml, certificate, 
				SignWithId,
				mrVersion,
				ElemForSign,
				ref idCounter,
				tagForSign,
				tagForSignNamespaceUri,
				namespaceIdAttr: NamespaceUri.OasisWSSecurityUtility
			);

			signedXml.NamespaceForReference = NamespaceUri.OasisWSSecurityUtility;
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			log.LogDebug($"Пытаемся получить значение SignatureMethod.");
			signedXml.SignedInfo.SignatureMethod = SignServiceUtils.GetSignatureMethod(SignServiceUtils.GetAlgId(certificate));
			log.LogDebug($"Значение SignatureMethod успешно получено: {signedXml.SignedInfo.SignatureMethod}.");

			XmlElement keyInfoElem = doc.CreateElement("KeyInfo", NamespaceUri.WSXmlDSig);
			XmlElement binaryTokenElem = doc.CreateElement("wsse", "BinarySecurityToken", NamespaceUri.OasisWSSecuritySecext);
			XmlElement tokenReferenceElem = doc.CreateElement("wsse", "SecurityTokenReference", NamespaceUri.OasisWSSecuritySecext);

			XmlElement referenceElem = doc.CreateElement("wsse", "Reference", NamespaceUri.OasisWSSecuritySecext);

			string certId = "uuid-" + Guid.NewGuid().ToString();
			XmlAttribute idAttr = doc.CreateAttribute("u", "Id", NamespaceUri.OasisWSSecurityUtility);
			XmlAttribute valueTypeTokenAttr = doc.CreateAttribute("ValueType");
			XmlAttribute encodingTypeTokenAttr = doc.CreateAttribute("EncodingType");

			idAttr.Value = certId;
			valueTypeTokenAttr.Value = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
			encodingTypeTokenAttr.Value = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
			binaryTokenElem.Attributes.Append((XmlAttribute)doc.ImportNode(idAttr, true));
			binaryTokenElem.Attributes.Append((XmlAttribute)doc.ImportNode(valueTypeTokenAttr, true));
			binaryTokenElem.Attributes.Append((XmlAttribute)doc.ImportNode(encodingTypeTokenAttr, true));

			X509Certificate2 cert = SignServiceUtils.GetX509Certificate2(certificate);
			binaryTokenElem.InnerText = Convert.ToBase64String(cert.RawData);

			XmlAttribute valueTypeAttr = doc.CreateAttribute("ValueType");
			valueTypeAttr.Value = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
			referenceElem.Attributes.Append((XmlAttribute)doc.ImportNode(valueTypeAttr, true));

			XmlAttribute uriAttr = doc.CreateAttribute("URI");
			uriAttr.Value = "#" + certId;
			referenceElem.Attributes.Append((XmlAttribute)doc.ImportNode(uriAttr, true));

			tokenReferenceElem.PrependChild(doc.ImportNode(referenceElem, true));

			keyInfoElem.PrependChild(doc.ImportNode(tokenReferenceElem, true));

			KeyInfoNode keyNode = new KeyInfoNode(tokenReferenceElem);
			KeyInfo keyInfo = new KeyInfo();
			keyInfo.AddClause(keyNode);
			signedXml.KeyInfo = keyInfo;
			signedXml.ComputeSignatureWithoutPrivateKey(xmldsigPrefix, certificate);

			XmlElement signatureElem = signedXml.GetXml(xmldsigPrefix);

			FillSignatureElement(doc, signatureElem, certificate, binaryTokenElem);

			SoapDSigUtil.AddActor(doc);

			return doc;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="signatureElem"></param>
		/// <param name="certificate"></param>
		/// <param name="token"></param>
		private void FillSignatureElement(XmlDocument doc, XmlElement signatureElem, IntPtr certificate, XmlElement token)
		{
			XmlElement wsseSecurity = doc.CreateElement("wsse", SignatureTags.SecurityTag, SignatureTags.SecurityNamespace);// <wsse:Security soap:actor="http://smev.gosuslugi.ru/actors/recipient" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
			XmlAttribute actorAttr = doc.CreateAttribute("soap", "actor", NamespaceUri.WSSoap11);

			// МР 2.4.5. Информационная система органа власти Потребителя или ПГУ при формировании
			// запроса к ИС поставщика, а также ИС Поставщика при формировании ответа должны
			// проставлять в атрибуте actor значение, соответствующее СМЭВ как стороне проверяющей
			// подпись: 
			// 38
			// soapenv:actor="http://smev.gosuslugi.ru/actors/smev"
			// СМЭВ при формировании электронной подписи в запросе при отправке его поставщику
			// или при отправке ответа к потребителю проставляет в атрибуте actor значение:
			// soapenv:actor="http://smev.gosuslugi.ru/actors/recipient"

			// МР 2.5.5. При взаимодействии на уровне регионального узла СМЭВ между региональными
			// участниками, подключенными к данному узлу, предусматриваются такие же правила
			// взаимодействия информационных систем участников с узлом РСМЭВ, как и для
			// федерального узла СМЭВ:
			// формирование ЭП-ОВ от имени ИС регионального участника осуществляется с
			// использованием атрибута actor="http://smev.gosuslugi.ru/actors/smev";
			// региональный узел СМЭВ формирует ЭП-РСМЭВ с использованием атрибута
			// actor="http://smev.gosuslugi.ru/actors/recipient" (данный формат является
			// локальным).
			actorAttr.Value = SmevAttributes.ActorSmev;
			wsseSecurity.Attributes.Append((XmlAttribute)doc.ImportNode(actorAttr, true));

			XmlElement keyInfoElem = doc.CreateElement("KeyInfo", NamespaceUri.WSXmlDSig);
			XmlElement binaryTokenElem = doc.CreateElement("wsse", "BinarySecurityToken", NamespaceUri.OasisWSSecuritySecext);
			XmlElement tokenReferenceElem = doc.CreateElement("wsse", "SecurityTokenReference", NamespaceUri.OasisWSSecuritySecext);

			XmlElement referenceElem = doc.CreateElement("wsse", "Reference", NamespaceUri.OasisWSSecuritySecext);

			string certId = "uuid-" + Guid.NewGuid().ToString();
			XmlAttribute idAttr = doc.CreateAttribute("u", "Id", NamespaceUri.OasisWSSecurityUtility);
			idAttr.Value = certId;
			binaryTokenElem.Attributes.Append((XmlAttribute)doc.ImportNode(idAttr, true));

			XmlAttribute valueTypeAttr = doc.CreateAttribute("ValueType");
			valueTypeAttr.Value = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
			referenceElem.Attributes.Append((XmlAttribute)doc.ImportNode(valueTypeAttr, true));

			XmlAttribute uriAttr = doc.CreateAttribute("URI"); // URI="#CertId-5F344A8A21BB6902C113550467558881327"
			uriAttr.Value = "#" + certId;
			referenceElem.Attributes.Append((XmlAttribute)doc.ImportNode(uriAttr, true));

			tokenReferenceElem.PrependChild(doc.ImportNode(referenceElem, true));

			keyInfoElem.PrependChild(doc.ImportNode(tokenReferenceElem, true));

			X509Certificate2 cert = SignServiceUtils.GetX509Certificate2(certificate);
			binaryTokenElem.InnerText = Convert.ToBase64String(cert.RawData);

			wsseSecurity.PrependChild(doc.ImportNode(signatureElem, true));

			wsseSecurity.PrependChild(doc.ImportNode(token, true));

			XmlElement headerElem = (XmlElement)doc.GetElementsByTagName("Header", NamespaceUri.WSSoap11)[0];

			if (headerElem == null)
			{
				headerElem = doc.CreateElement("Header", NamespaceUri.WSSoap11);
				doc.DocumentElement.PrependChild(headerElem);
			}

			RemoveSecurityBodes(headerElem);

			headerElem.PrependChild(doc.ImportNode(wsseSecurity, true));
		}

		/// <summary>
		/// Удаление тэгов Security (подпись) из запроса.
		/// </summary>
		/// <param name="node">Тэг из которого надо убрать все подписи.</param>
		private void RemoveSecurityBodes(XmlElement node)
		{
			// Получаем тэги Security.
			XmlNodeList nodeList = node.GetElementsByTagName(SignatureTags.SecurityTag, SignatureTags.SecurityNamespace);
			SmevXmlHelper.RemoveNodes(node, nodeList);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="doc"></param>
		/// <param name="signedXml"></param>
		/// <param name="certificate"></param>
		/// <param name="customTag"></param>
		/// <param name="customNamespace"></param>
		/// <param name="namespaceIdAttr"></param>
		/// <returns></returns>
		//private SignedXml AddReference(XmlDocument doc, SignedXml signedXml, IntPtr certificate, string customTag = "", string customNamespace = "", string namespaceIdAttr = "")
		//{
		//	Reference reference = new Reference();
		//	string id = string.Empty;

		//	if (this.ElemForSign == SignedTag.CustomTag && string.IsNullOrEmpty(customTag) != true)
		//	{
		//		id = SmevXmlHelper.GetElemId(doc, customTag, customNamespace, SignWithId, namespaceIdAttr);

		//		if (string.IsNullOrEmpty(id) && this.SignWithId)
		//		{
		//			id = "#" + SmevXmlHelper.SetElemId(doc, customTag, this.tagForSignNamespaceUri, SignWithId, mrVersion, ref idCounter, "", namespaceIdAttr);
		//		}
		//	}
		//	else
		//	{
		//		id = SmevXmlHelper.GetElemId(doc, this.tagForSign, this.tagForSignNamespaceUri, SignWithId, namespaceIdAttr);

		//		if (string.IsNullOrEmpty(id) && this.SignWithId)
		//		{
		//			id = "#" + SmevXmlHelper.SetElemId(doc, this.tagForSign, this.tagForSignNamespaceUri, SignWithId, mrVersion, ref idCounter, "", namespaceIdAttr);
		//		}
		//	}

		//	reference.Uri = (SignWithId) ? id : string.Empty;
		//	reference.DigestMethod = SignServiceUtils.GetDigestMethod(SignServiceUtils.GetAlgId(certificate));

		//	if (string.IsNullOrEmpty(customTag) != true && this.ElemForSign == SignedTag.CustomTag)
		//	{
		//		XmlDsigEnvelopedSignatureTransform envelop = new XmlDsigEnvelopedSignatureTransform();
		//		reference.AddTransform(envelop);
		//	}

		//	XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
		//	reference.AddTransform(c14);

		//	if (this.mrVersion == Mr.MR300)
		//	{
		//		SmevTransformAlg smevTransform = new SmevTransformAlg();
		//		reference.AddTransform(smevTransform);
		//	}

		//	signedXml.AddReference(reference);

		//	return signedXml;
		//}

		/// <summary>
		/// Метод поиска тэга для подписи
		/// </summary>
		/// <param name="doc"></param>
		/// <returns></returns>
		private string FindSmevTagForSign(XmlDocument doc)
		{
			string result = string.Empty;

			if (this.mrVersion == Mr.MR244 || this.mrVersion == Mr.MR255)
			{
				this.tagForSignNamespaceUri = NamespaceUri.WSSoap11;

				if (this.ElemForSign == SignedTag.Body)
				{
					result = SmevMr2xxTags.Body;
				}
				else if (this.ElemForSign == SignedTag.AppData)
				{
					result = SmevMr2xxTags.AppData;
				}
			}

			return result;
		}
	}
}
