using System;

namespace SignOVService.Model.Smev.Sign
{
	/// <summary>
	/// Класс-заглушка. Изменится, когда будет полная документация по СМЭВ 3.
	/// </summary>
	public class SmevMr3xxTags
	{
		public static string[] GetAllSignTags()
		{
			string[] allTags = new string[]
			{
				SenderProvidedRequestData,
				SenderProvidedResponseData,
				Timestamp,
				MessageTypeSelector,
				AckTargetMessage
			};

			return allTags;
		}

		public static string[] GetAllRequestTags()
		{
			string[] allTags = new string[]
			{
				SendRequestRequest,
				SendResponseRequest,
				GetStatusRequest,
				GetRequestRequest,
				GetResponseRequest,
				AckRequest,
				GetIncomingQueueStatisticsRequest
			};

			return allTags;
		}

		public static string[] GetSignTagByRequestTag(string requestTag)
		{
			string[] result = null;

			if (string.Compare(requestTag, SendRequestRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { SenderProvidedRequestData };
			}
			else if (string.Compare(requestTag, SendResponseRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { SenderProvidedResponseData };
			}
			else if (string.Compare(requestTag, GetStatusRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { Timestamp };
			}
			else if (string.Compare(requestTag, GetRequestRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { MessageTypeSelector };
			}
			else if (string.Compare(requestTag, GetResponseRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { MessageTypeSelector };
			}
			else if (string.Compare(requestTag, AckRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { AckTargetMessage };
			}
			else if (string.Compare(requestTag, GetIncomingQueueStatisticsRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { Timestamp };
			}

			return result;
		}

		public static string[] GetRequestTagBySignTag(string signTag)
		{
			string[] result = null;

			if (string.Compare(signTag, SenderProvidedRequestData, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { SendRequestRequest };
			}
			else if (string.Compare(signTag, SenderProvidedResponseData, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { SendResponseRequest };
			}
			else if (string.Compare(signTag, Timestamp, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { GetStatusRequest, GetIncomingQueueStatisticsRequest };
			}
			else if (string.Compare(signTag, MessageTypeSelector, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { GetRequestRequest, GetResponseRequest };
			}
			else if (string.Compare(signTag, AckTargetMessage, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = new string[] { AckRequest };
			}

			return result;
		}

		public static string GetNamespaceTagByTag(string targetTag)
		{
			string result = NamespaceUri.Smev3Types;

			if (string.Compare(targetTag, SenderProvidedRequestData, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, SenderProvidedResponseData, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, Timestamp, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = NamespaceUri.Smev3TypesBasic;
			}
			else if (string.Compare(targetTag, MessageTypeSelector, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = NamespaceUri.Smev3TypesBasic;
			}
			else if (string.Compare(targetTag, AckTargetMessage, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = NamespaceUri.Smev3TypesBasic;
			}
			else if (string.Compare(targetTag, SendRequestRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, SendResponseRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, GetStatusRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, GetRequestRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, GetResponseRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, AckRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}
			else if (string.Compare(targetTag, GetIncomingQueueStatisticsRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
			}

			return result;
		}

		public static bool IsRequestSignaturePrecedingSibling(string requestTag)
		{
			bool result = false;

			if (string.Compare(requestTag, AckRequest, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = true;
			}

			return result;
		}

		public static bool IsTagSignaturePrecedingSibling(string signTag)
		{
			bool result = false;

			if (string.Compare(signTag, AckTargetMessage, StringComparison.InvariantCultureIgnoreCase) == 0)
			{
				result = true;
			}

			return result;
		}

		public static readonly string SenderProvidedRequestData = "SenderProvidedRequestData"; // SendRequestRequest

		public static readonly string SenderProvidedResponseData = "SenderProvidedResponseData"; // SendResponseRequest

		public static readonly string Timestamp = "Timestamp"; // GetStatusRequest

		public static readonly string MessageTypeSelector = "MessageTypeSelector"; // GetRequestRequest // GetResponseRequest

		public static readonly string AckTargetMessage = "AckTargetMessage"; // AckRequest

		public static readonly string SendRequestRequest = "SendRequestRequest"; // SenderProvidedRequestData

		public static readonly string SendResponseRequest = "SendResponseRequest"; // SenderProvidedResponseData

		public static readonly string GetStatusRequest = "GetStatusRequest"; // Timestamp

		public static readonly string GetRequestRequest = "GetRequestRequest"; // MessageTypeSelector

		public static readonly string GetResponseRequest = "GetResponseRequest"; // MessageTypeSelector

		public static readonly string AckRequest = "AckRequest"; // AckTargetMessage

		public static readonly string GetIncomingQueueStatisticsRequest = "GetIncomingQueueStatisticsRequest"; // Timestamp

		public static readonly string InformationSystemSignatureId = "SIGNED_BY_CALLER";

		public static readonly string PersonalSignatureId = "PERSONAL_SIGNATURE";
	}
}
