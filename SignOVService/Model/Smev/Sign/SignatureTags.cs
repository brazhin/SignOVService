namespace SignOVService.Model.Smev.Sign
{
	public class SignatureTags
	{
		public static readonly string CallerInformationSystemSignatureNamespace = NamespaceUri.Smev3Types;

		public static readonly string CallerInformationSystemSignatureTag = "CallerInformationSystemSignature";

		public static readonly string SMEVSignatureSignatureTag = "SMEVSignature";

		public static readonly string SenderInformationSystemSignatureTag = "SenderInformationSystemSignature";

		public static readonly string PersonalSignatureNamespace = NamespaceUri.Smev3Types;

		public static readonly string PersonalSignatureTag = "PersonalSignature";

		public static readonly string SecurityNamespace = NamespaceUri.OasisWSSecuritySecext;

		public static readonly string SecurityTag = "Security";

		public static readonly string SignatureNamespace = NamespaceUri.WSXmlDSig;

		public static readonly string SignatureTag = "Signature";
	}
}
