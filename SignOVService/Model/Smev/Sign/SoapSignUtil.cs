using SignOVService.Model.Smev.Sign.SoapSigners;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace SignOVService.Model.Smev.Sign
{
	public class SoapSignUtil
	{
		// Объект, через который происходит подписание
		private ISoapSigner signerTool;

		// По умолчанию подписыванием тело XML содержимого
		public SignedTag ElemForSign = SignedTag.Body;
		public bool SignWithId = false;

		public SoapSignUtil(X509Certificate2 certificate, MR mr)
		{
			MrVersion = mr;
			Certificate = certificate;

			switch (MrVersion)
			{
				case MR.MR244:
					//signerTool = new SoapSignUtil2XX(mr);
					break;
				case MR.MR255:
					//signerTool = new SoapSignUtil2XX(mr);
					break;
				case MR.MR300:
					signerTool = new SoapSignUtil3XX(mr);
					break;
				default:
					throw new NotImplementedException("Неподдерживаемая версия методических рекомендаций.");
			}
		}

		public MR MrVersion { get; }
		public X509Certificate2 Certificate { get; private set; }

		/// <summary>
		/// Метод запускает подписание запроса для определенной версии МР, установленной в конструкторе
		/// </summary>
		/// <param name="doc"></param>
		/// <returns></returns>
		internal XmlDocument SignMessage(XmlDocument doc)
		{
			try
			{
				signerTool.ElemForSign = ElemForSign;
				signerTool.SignWithId = SignWithId;

				return signerTool.SignMessageAsOv(doc, Certificate);
			}
			catch (Exception ex)
			{
				//TODO: log
				throw ex;
			}
		}
	}
}
