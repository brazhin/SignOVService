using Microsoft.Extensions.Logging;
using System;

namespace SignService.Smev.XmlSigners
{
	/// <summary>
	/// Класс для создания клиентов подписи для определенной версии МР
	/// </summary>
	internal static class SignerXmlHelper
	{
		internal static ISignerXml CreateSigner(Mr mr, ILoggerFactory loggerFactory)
		{
			if (mr == Mr.MR244)
				return new SignerXml2XX(Mr.MR244, loggerFactory);
			else if (mr == Mr.MR255)
				return new SignerXml2XX(Mr.MR255, loggerFactory);
			else if (mr == Mr.MR300)
				return new SignerXml3XX(loggerFactory);
			else
				throw new ArgumentException($"Неподдерживаемая версия МР {mr}.");
		}
	}
}
