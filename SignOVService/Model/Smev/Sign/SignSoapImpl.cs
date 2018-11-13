using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model.Smev.Sign
{
	public class SignSoapImpl
	{
		private readonly ILogger<SignSoapImpl> log;
		private readonly SoapSignUtil senderSignUtil;

		public SignSoapImpl(ILoggerFactory loggerFactory, X509Certificate2 currentCertificate, MR mR)
		{
			this.log = loggerFactory.CreateLogger<SignSoapImpl>();

			this.Certificate = currentCertificate;
			this.senderSignUtil = new SoapSignUtil(loggerFactory, Certificate, mR);
		}

		public X509Certificate2 Certificate { get; }

		/// <summary>
		/// Метод подписания, модифицирует xml перед подписанием и после подписания в случае если версия мр == 244 или 255
		/// </summary>
		/// <param name="soap"></param>
		/// <returns></returns>
		public XmlDocument SignSoapOV(XmlDocument soap)
		{
			log.LogDebug("Выполняем метод SignSoapImpl.SignSoapOV.");

			string message = soap.OuterXml;

			if (senderSignUtil.MrVersion == MR.MR244 || senderSignUtil.MrVersion == MR.MR255)
			{
				log.LogDebug($"Версия МР: {senderSignUtil.MrVersion}, выполняем удаление тэга <Actor> перед подписанием.");
				message = SoapDSigUtil.RemoveActor(soap);
			}

			log.LogDebug("Получаем XML содержимое для подписи.");

			XmlDocument doc = new XmlDocument { PreserveWhitespace = true };
			doc.LoadXml(message);

			log.LogDebug("XML содержимое для подписи успешно получено.");

			senderSignUtil.ElemForSign = SignedTag.Body;
			senderSignUtil.SignWithId = true;

			log.LogDebug("Отправляем XML содержимое на подпись.");

			doc = senderSignUtil.SignMessage(doc);

			log.LogDebug("Содержимое XML было успешно подписано.");

			if (senderSignUtil.MrVersion == MR.MR244 || senderSignUtil.MrVersion == MR.MR255)
			{
				log.LogDebug($"Версия МР: {senderSignUtil.MrVersion}, выполняем добавление тэга <Actor> после подписания.");
				SoapDSigUtil.AddActor(doc);
			}

			return doc;
		}
	}
}
