using Microsoft.Extensions.Logging;
using SignService.CommonUtils;
using SignService.Smev.Utils;
using SignService.Smev.SoapSigners.SignedXmlExt;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignService.Smev.SoapSigners
{
	/// <summary>
	/// Реализация подписи XML для СМЭВ2
	/// </summary>
	internal class SignerSoap2XX : ISignerXml
	{
		private readonly ILogger<SignerSoap2XX> log;
		private const string xmldsigPrefix = "ds";

		private readonly Mr mrVersion;
		
		private string mrNamespace;
		private string securityNamespace = NamespaceUri.OasisWSSecurityUtility;
		private string tagForSign = string.Empty;
		private string tagForSignNamespaceUri = string.Empty;

		private int idCounter = 1;

		private Dictionary<Mr, string> mrText = new Dictionary<Mr, string>()
		{
			{ Mr.MR244, "MR244" },
			{ Mr.MR255, "MR255" }
		};

		/// <summary>
		/// Конструктор класса
		/// </summary>
		/// <param name="mr"></param>
		/// <param name="loggerFactory"></param>
		internal SignerSoap2XX(Mr mr, ILoggerFactory loggerFactory)
		{
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

			this.log = loggerFactory.CreateLogger<SignerSoap2XX>();
		}

		public SignedTag ElemForSign { get; set; } = SignedTag.Body;
		public bool SignWithId { get; set; } = true;

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
					throw new NotImplementedException("Неподдерживаемая версия методических рекомендаций.");
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
			try
			{
				// Удаляем тэг Actor
				string message = string.Empty;

				try
				{
					log.LogDebug("Пытаемся удалить атрибут 'Actor'.");
					message = SoapDSigUtil.RemoveActor(xml);
					log.LogDebug("Атрибут 'Actor' успешно удален.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке удалить атрибут 'Actor'. {ex.Message}.");
				}

				XmlDocument doc = new XmlDocument() { PreserveWhitespace = true };

				try
				{
					doc.LoadXml(message);
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при формировании XML после удаления атрибута 'Actor'. {ex.Message}.");
				}

				try
				{
					log.LogDebug("Получаем значение тэга для подписи.");
					this.tagForSign = this.FindSmevTagForSign(doc);
					log.LogDebug($"Значение тэга для подписи получено. {tagForSign}.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке получить тэг с элементом для подписи. {ex.Message}.");
				}

				SmevSignedXml signedXml = new SmevSignedXml(doc);

				try
				{
					log.LogDebug($"Выполняем добавление элемента Reference в XML.");

					signedXml = (SmevSignedXml)SmevXmlHelper.AddReference(doc, signedXml, certificate,
						SignWithId,
						mrVersion,
						ElemForSign,
						ref idCounter,
						tagForSign,
						tagForSignNamespaceUri,
						namespaceIdAttr: NamespaceUri.OasisWSSecurityUtility
					);

					log.LogDebug($"Добавление элемента Reference в XML выполнено успешно.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке добавить элемент Reference. {ex.Message}.");
				}

				signedXml.NamespaceForReference = NamespaceUri.OasisWSSecurityUtility;
				signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

				try
				{
					log.LogDebug($"Пытаемся получить значение SignatureMethod.");
					signedXml.SignedInfo.SignatureMethod = SignServiceUtils.GetSignatureMethod(SignServiceUtils.GetAlgId(certificate));
					log.LogDebug($"Значение SignatureMethod успешно получено: {signedXml.SignedInfo.SignatureMethod}.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке получить значение метода подписи. {ex.Message}.");
				}

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

				try
				{
					KeyInfoNode keyNode = new KeyInfoNode(tokenReferenceElem);
					KeyInfo keyInfo = new KeyInfo();
					keyInfo.AddClause(keyNode);
					signedXml.KeyInfo = keyInfo;
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при формировании элемента KeyInfo. {ex.Message}.");
				}

				try
				{
					log.LogDebug($"Пытаемся вычислить подпись.");
					signedXml.ComputeSignatureWithoutPrivateKey(xmldsigPrefix, certificate);
					log.LogDebug($"Вычисление подписи выполнено успешно.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке вычислить подпись для XML. {ex.Message}.");
				}

				XmlElement signatureElem = null;

				try
				{
					log.LogDebug("Пытаемся получить элемент с подписью.");
					signatureElem = signedXml.GetXml(xmldsigPrefix);
					log.LogDebug("Элемент с подписью успешно получен.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке получить элемент содержащий подпись. {ex.Message}.");
				}

				try
				{
					log.LogDebug("Пытаемся добавить подпись в XML содержимое.");
					FillSignatureElement(doc, signatureElem, certificate, binaryTokenElem);
					log.LogDebug("Подпись успешно добавлена.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке заполнить XML информацией о подписи. {ex.Message}.");
				}

				try
				{
					log.LogDebug("Пытаемся добавить атрибут 'Actor'.");
					SoapDSigUtil.AddActor(doc);
					log.LogDebug("Атрибут 'Actor' успешно добавлен.");
				}
				catch (Exception ex)
				{
					throw new Exception($"Ошибка при попытке добавить атрибут 'Actor'. {ex.Message}.");
				}

				return doc;
			}
			catch(Exception ex)
			{
				log.LogError($"Ошибка при попытке подписать XML. {ex.Message}.");
				throw new CryptographicException($"Ошибка при попытке подписать XML для версии {mrText[mrVersion]}. {ex.Message}.");
			}
		}

		/// <summary>
		/// Добавляет тэг с подписью целиком. Сертификат должен быть в тэге подписи.
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
