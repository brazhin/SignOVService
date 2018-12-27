using SignService.Smev.SoapSigners.SignedXmlExt;

namespace SignService.Smev
{
	internal class SmevMr2xxTags
	{
		public static string[] GetAllTags()
		{
			string[] allTags = new string[]
			{
				Body ,
				AppData
			};

			return allTags;
		}

		public static readonly string Body = "Body";

		public static readonly string BodyNamespace = NamespaceUri.WSSoap11;

		public static readonly string AppData = "AppData";
	}
}
